rule TTP_XOR_MULT_DOSStub_039f {
  strings:
    $key_039f = { 57 f7 [2] 23 ef [2] 64 ed [2] 23 fc [2] 6d f0 [2] 61 fa [2] 76 f1 [2] 6d bf [2] 50 }

  condition:
    any of them
}