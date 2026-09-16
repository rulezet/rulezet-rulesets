rule TTP_XOR_MULT_DOSStub_7327 {
  strings:
    $key_7327 = { 27 4f [2] 53 57 [2] 14 55 [2] 53 44 [2] 1d 48 [2] 11 42 [2] 06 49 [2] 1d 07 [2] 20 }

  condition:
    any of them
}