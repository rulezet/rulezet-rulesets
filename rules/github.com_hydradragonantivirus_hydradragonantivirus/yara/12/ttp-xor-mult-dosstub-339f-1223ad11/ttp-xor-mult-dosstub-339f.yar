rule TTP_XOR_MULT_DOSStub_339f {
  strings:
    $key_339f = { 67 f7 [2] 13 ef [2] 54 ed [2] 13 fc [2] 5d f0 [2] 51 fa [2] 46 f1 [2] 5d bf [2] 60 }

  condition:
    any of them
}