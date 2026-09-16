rule TTP_XOR_MULT_DOSStub_aad2 {
  strings:
    $key_aad2 = { fe ba [2] 8a a2 [2] cd a0 [2] 8a b1 [2] c4 bd [2] c8 b7 [2] df bc [2] c4 f2 [2] f9 }

  condition:
    any of them
}