rule TTP_XOR_MULT_DOSStub_f0a0 {
  strings:
    $key_f0a0 = { a4 c8 [2] d0 d0 [2] 97 d2 [2] d0 c3 [2] 9e cf [2] 92 c5 [2] 85 ce [2] 9e 80 [2] a3 }

  condition:
    any of them
}