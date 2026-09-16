rule TTP_XOR_MULT_DOSStub_733d {
  strings:
    $key_733d = { 27 55 [2] 53 4d [2] 14 4f [2] 53 5e [2] 1d 52 [2] 11 58 [2] 06 53 [2] 1d 1d [2] 20 }

  condition:
    any of them
}