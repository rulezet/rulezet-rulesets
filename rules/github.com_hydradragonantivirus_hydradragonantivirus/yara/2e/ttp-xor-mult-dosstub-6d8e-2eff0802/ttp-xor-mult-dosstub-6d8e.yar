rule TTP_XOR_MULT_DOSStub_6d8e {
  strings:
    $key_6d8e = { 39 e6 [2] 4d fe [2] 0a fc [2] 4d ed [2] 03 e1 [2] 0f eb [2] 18 e0 [2] 03 ae [2] 3e }

  condition:
    any of them
}