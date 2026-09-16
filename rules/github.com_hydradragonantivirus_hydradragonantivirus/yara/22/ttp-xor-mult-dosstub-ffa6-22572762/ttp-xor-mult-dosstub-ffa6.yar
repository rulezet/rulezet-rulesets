rule TTP_XOR_MULT_DOSStub_ffa6 {
  strings:
    $key_ffa6 = { ab ce [2] df d6 [2] 98 d4 [2] df c5 [2] 91 c9 [2] 9d c3 [2] 8a c8 [2] 91 86 [2] ac }

  condition:
    any of them
}