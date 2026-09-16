rule TTP_XOR_MULT_DOSStub_a988 {
  strings:
    $key_a988 = { fd e0 [2] 89 f8 [2] ce fa [2] 89 eb [2] c7 e7 [2] cb ed [2] dc e6 [2] c7 a8 [2] fa }

  condition:
    any of them
}