rule TTP_XOR_MULT_DOSStub_9886 {
  strings:
    $key_9886 = { cc ee [2] b8 f6 [2] ff f4 [2] b8 e5 [2] f6 e9 [2] fa e3 [2] ed e8 [2] f6 a6 [2] cb }

  condition:
    any of them
}