rule TTP_XOR_MULT_DOSStub_418e {
  strings:
    $key_418e = { 15 e6 [2] 61 fe [2] 26 fc [2] 61 ed [2] 2f e1 [2] 23 eb [2] 34 e0 [2] 2f ae [2] 12 }

  condition:
    any of them
}