rule TTP_XOR_MULT_DOSStub_7310 {
  strings:
    $key_7310 = { 27 78 [2] 53 60 [2] 14 62 [2] 53 73 [2] 1d 7f [2] 11 75 [2] 06 7e [2] 1d 30 [2] 20 }

  condition:
    any of them
}