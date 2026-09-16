rule TTP_XOR_MULT_DOSStub_439f {
  strings:
    $key_439f = { 17 f7 [2] 63 ef [2] 24 ed [2] 63 fc [2] 2d f0 [2] 21 fa [2] 36 f1 [2] 2d bf [2] 10 }

  condition:
    any of them
}