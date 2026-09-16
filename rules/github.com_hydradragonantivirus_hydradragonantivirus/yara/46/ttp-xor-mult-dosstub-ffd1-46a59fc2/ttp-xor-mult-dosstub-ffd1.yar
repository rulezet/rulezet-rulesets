rule TTP_XOR_MULT_DOSStub_ffd1 {
  strings:
    $key_ffd1 = { ab b9 [2] df a1 [2] 98 a3 [2] df b2 [2] 91 be [2] 9d b4 [2] 8a bf [2] 91 f1 [2] ac }

  condition:
    any of them
}