rule TTP_XOR_MULT_DOSStub_e39f {
  strings:
    $key_e39f = { b7 f7 [2] c3 ef [2] 84 ed [2] c3 fc [2] 8d f0 [2] 81 fa [2] 96 f1 [2] 8d bf [2] b0 }

  condition:
    any of them
}