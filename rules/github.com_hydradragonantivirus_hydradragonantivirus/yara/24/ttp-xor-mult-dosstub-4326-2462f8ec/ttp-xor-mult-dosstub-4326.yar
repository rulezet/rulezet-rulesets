rule TTP_XOR_MULT_DOSStub_4326 {
  strings:
    $key_4326 = { 17 4e [2] 63 56 [2] 24 54 [2] 63 45 [2] 2d 49 [2] 21 43 [2] 36 48 [2] 2d 06 [2] 10 }

  condition:
    any of them
}