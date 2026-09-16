rule TTP_XOR_MULT_DOSStub_1d8e {
  strings:
    $key_1d8e = { 49 e6 [2] 3d fe [2] 7a fc [2] 3d ed [2] 73 e1 [2] 7f eb [2] 68 e0 [2] 73 ae [2] 4e }

  condition:
    any of them
}