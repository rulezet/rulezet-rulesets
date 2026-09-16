rule TTP_XOR_MULT_DOSStub_aa80 {
  strings:
    $key_aa80 = { fe e8 [2] 8a f0 [2] cd f2 [2] 8a e3 [2] c4 ef [2] c8 e5 [2] df ee [2] c4 a0 [2] f9 }

  condition:
    any of them
}