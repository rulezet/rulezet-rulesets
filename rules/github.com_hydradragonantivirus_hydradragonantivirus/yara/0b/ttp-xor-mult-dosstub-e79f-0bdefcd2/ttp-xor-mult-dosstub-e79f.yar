rule TTP_XOR_MULT_DOSStub_e79f {
  strings:
    $key_e79f = { b3 f7 [2] c7 ef [2] 80 ed [2] c7 fc [2] 89 f0 [2] 85 fa [2] 92 f1 [2] 89 bf [2] b4 }

  condition:
    any of them
}