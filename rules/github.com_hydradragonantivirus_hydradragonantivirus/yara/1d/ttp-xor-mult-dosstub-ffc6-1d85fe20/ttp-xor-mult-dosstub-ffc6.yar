rule TTP_XOR_MULT_DOSStub_ffc6 {
  strings:
    $key_ffc6 = { ab ae [2] df b6 [2] 98 b4 [2] df a5 [2] 91 a9 [2] 9d a3 [2] 8a a8 [2] 91 e6 [2] ac }

  condition:
    any of them
}