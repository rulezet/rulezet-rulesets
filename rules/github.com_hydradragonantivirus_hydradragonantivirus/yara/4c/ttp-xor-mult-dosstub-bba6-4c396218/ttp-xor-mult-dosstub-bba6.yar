rule TTP_XOR_MULT_DOSStub_bba6 {
  strings:
    $key_bba6 = { ef ce [2] 9b d6 [2] dc d4 [2] 9b c5 [2] d5 c9 [2] d9 c3 [2] ce c8 [2] d5 86 [2] e8 }

  condition:
    any of them
}