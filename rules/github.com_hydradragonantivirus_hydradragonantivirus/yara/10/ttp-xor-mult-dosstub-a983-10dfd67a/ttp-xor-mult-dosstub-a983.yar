rule TTP_XOR_MULT_DOSStub_a983 {
  strings:
    $key_a983 = { fd eb [2] 89 f3 [2] ce f1 [2] 89 e0 [2] c7 ec [2] cb e6 [2] dc ed [2] c7 a3 [2] fa }

  condition:
    any of them
}