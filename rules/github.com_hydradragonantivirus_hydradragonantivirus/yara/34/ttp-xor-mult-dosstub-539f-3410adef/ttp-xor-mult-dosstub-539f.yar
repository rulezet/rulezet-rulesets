rule TTP_XOR_MULT_DOSStub_539f {
  strings:
    $key_539f = { 07 f7 [2] 73 ef [2] 34 ed [2] 73 fc [2] 3d f0 [2] 31 fa [2] 26 f1 [2] 3d bf [2] 00 }

  condition:
    any of them
}