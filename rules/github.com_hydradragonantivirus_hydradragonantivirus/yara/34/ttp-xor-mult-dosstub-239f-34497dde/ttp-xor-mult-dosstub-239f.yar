rule TTP_XOR_MULT_DOSStub_239f {
  strings:
    $key_239f = { 77 f7 [2] 03 ef [2] 44 ed [2] 03 fc [2] 4d f0 [2] 41 fa [2] 56 f1 [2] 4d bf [2] 70 }

  condition:
    any of them
}