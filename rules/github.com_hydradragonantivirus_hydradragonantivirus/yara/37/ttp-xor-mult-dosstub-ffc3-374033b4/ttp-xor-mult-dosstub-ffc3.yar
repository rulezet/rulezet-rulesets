rule TTP_XOR_MULT_DOSStub_ffc3 {
  strings:
    $key_ffc3 = { ab ab [2] df b3 [2] 98 b1 [2] df a0 [2] 91 ac [2] 9d a6 [2] 8a ad [2] 91 e3 [2] ac }

  condition:
    any of them
}