rule TTP_XOR_MULT_DOSStub_5d8e {
  strings:
    $key_5d8e = { 09 e6 [2] 7d fe [2] 3a fc [2] 7d ed [2] 33 e1 [2] 3f eb [2] 28 e0 [2] 33 ae [2] 0e }

  condition:
    any of them
}