rule TTP_XOR_MULT_DOSStub_aadb {
  strings:
    $key_aadb = { fe b3 [2] 8a ab [2] cd a9 [2] 8a b8 [2] c4 b4 [2] c8 be [2] df b5 [2] c4 fb [2] f9 }

  condition:
    any of them
}