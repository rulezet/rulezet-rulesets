rule TTP_XOR_MULT_DOSStub_bb97 {
  strings:
    $key_bb97 = { ef ff [2] 9b e7 [2] dc e5 [2] 9b f4 [2] d5 f8 [2] d9 f2 [2] ce f9 [2] d5 b7 [2] e8 }

  condition:
    any of them
}