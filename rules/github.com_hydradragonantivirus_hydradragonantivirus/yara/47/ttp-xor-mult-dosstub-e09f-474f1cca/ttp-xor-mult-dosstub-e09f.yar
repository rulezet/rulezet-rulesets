rule TTP_XOR_MULT_DOSStub_e09f {
  strings:
    $key_e09f = { b4 f7 [2] c0 ef [2] 87 ed [2] c0 fc [2] 8e f0 [2] 82 fa [2] 95 f1 [2] 8e bf [2] b3 }

  condition:
    any of them
}