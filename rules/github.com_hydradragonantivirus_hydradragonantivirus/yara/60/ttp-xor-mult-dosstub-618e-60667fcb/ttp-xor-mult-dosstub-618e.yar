rule TTP_XOR_MULT_DOSStub_618e {
  strings:
    $key_618e = { 35 e6 [2] 41 fe [2] 06 fc [2] 41 ed [2] 0f e1 [2] 03 eb [2] 14 e0 [2] 0f ae [2] 32 }

  condition:
    any of them
}