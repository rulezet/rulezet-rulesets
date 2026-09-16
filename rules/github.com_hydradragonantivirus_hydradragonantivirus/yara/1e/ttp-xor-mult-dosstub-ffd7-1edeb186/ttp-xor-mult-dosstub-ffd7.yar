rule TTP_XOR_MULT_DOSStub_ffd7 {
  strings:
    $key_ffd7 = { ab bf [2] df a7 [2] 98 a5 [2] df b4 [2] 91 b8 [2] 9d b2 [2] 8a b9 [2] 91 f7 [2] ac }

  condition:
    any of them
}