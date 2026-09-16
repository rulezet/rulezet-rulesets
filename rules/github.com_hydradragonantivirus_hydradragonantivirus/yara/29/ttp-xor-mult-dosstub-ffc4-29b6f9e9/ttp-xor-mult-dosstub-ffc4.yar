rule TTP_XOR_MULT_DOSStub_ffc4 {
  strings:
    $key_ffc4 = { ab ac [2] df b4 [2] 98 b6 [2] df a7 [2] 91 ab [2] 9d a1 [2] 8a aa [2] 91 e4 [2] ac }

  condition:
    any of them
}