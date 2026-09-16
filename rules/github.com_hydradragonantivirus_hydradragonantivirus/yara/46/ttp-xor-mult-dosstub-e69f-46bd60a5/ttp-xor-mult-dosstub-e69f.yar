rule TTP_XOR_MULT_DOSStub_e69f {
  strings:
    $key_e69f = { b2 f7 [2] c6 ef [2] 81 ed [2] c6 fc [2] 88 f0 [2] 84 fa [2] 93 f1 [2] 88 bf [2] b5 }

  condition:
    any of them
}