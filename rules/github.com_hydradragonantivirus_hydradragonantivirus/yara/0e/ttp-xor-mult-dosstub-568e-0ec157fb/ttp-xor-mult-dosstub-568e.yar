rule TTP_XOR_MULT_DOSStub_568e {
  strings:
    $key_568e = { 02 e6 [2] 76 fe [2] 31 fc [2] 76 ed [2] 38 e1 [2] 34 eb [2] 23 e0 [2] 38 ae [2] 05 }

  condition:
    any of them
}