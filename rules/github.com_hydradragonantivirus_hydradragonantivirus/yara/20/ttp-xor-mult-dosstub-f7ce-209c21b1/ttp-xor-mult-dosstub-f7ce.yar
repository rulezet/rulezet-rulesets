rule TTP_XOR_MULT_DOSStub_f7ce {
  strings:
    $key_f7ce = { a3 a6 [2] d7 be [2] 90 bc [2] d7 ad [2] 99 a1 [2] 95 ab [2] 82 a0 [2] 99 ee [2] a4 }

  condition:
    any of them
}