rule TTP_XOR_MULT_DOSStub_ffd4 {
  strings:
    $key_ffd4 = { ab bc [2] df a4 [2] 98 a6 [2] df b7 [2] 91 bb [2] 9d b1 [2] 8a ba [2] 91 f4 [2] ac }

  condition:
    any of them
}