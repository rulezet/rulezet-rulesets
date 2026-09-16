rule TTP_XOR_MULT_DOSStub_a993 {
  strings:
    $key_a993 = { fd fb [2] 89 e3 [2] ce e1 [2] 89 f0 [2] c7 fc [2] cb f6 [2] dc fd [2] c7 b3 [2] fa }

  condition:
    any of them
}