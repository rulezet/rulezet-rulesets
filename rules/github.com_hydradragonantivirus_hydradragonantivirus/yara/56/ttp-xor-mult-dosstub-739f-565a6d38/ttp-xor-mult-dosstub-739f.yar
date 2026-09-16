rule TTP_XOR_MULT_DOSStub_739f {
  strings:
    $key_739f = { 27 f7 [2] 53 ef [2] 14 ed [2] 53 fc [2] 1d f0 [2] 11 fa [2] 06 f1 [2] 1d bf [2] 20 }

  condition:
    any of them
}