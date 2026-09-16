rule TTP_XOR_MULT_DOSStub_f6a0 {
  strings:
    $key_f6a0 = { a2 c8 [2] d6 d0 [2] 91 d2 [2] d6 c3 [2] 98 cf [2] 94 c5 [2] 83 ce [2] 98 80 [2] a5 }

  condition:
    any of them
}