rule TTP_XOR_MULT_DOSStub_508e {
  strings:
    $key_508e = { 04 e6 [2] 70 fe [2] 37 fc [2] 70 ed [2] 3e e1 [2] 32 eb [2] 25 e0 [2] 3e ae [2] 03 }

  condition:
    any of them
}