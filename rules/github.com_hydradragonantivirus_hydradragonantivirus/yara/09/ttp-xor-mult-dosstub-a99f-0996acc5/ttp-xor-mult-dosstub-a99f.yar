rule TTP_XOR_MULT_DOSStub_a99f {
  strings:
    $key_a99f = { fd f7 [2] 89 ef [2] ce ed [2] 89 fc [2] c7 f0 [2] cb fa [2] dc f1 [2] c7 bf [2] fa }

  condition:
    any of them
}