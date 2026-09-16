rule TTP_XOR_MULT_DOSStub_ffd9 {
  strings:
    $key_ffd9 = { ab b1 [2] df a9 [2] 98 ab [2] df ba [2] 91 b6 [2] 9d bc [2] 8a b7 [2] 91 f9 [2] ac }

  condition:
    any of them
}