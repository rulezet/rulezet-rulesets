rule TTP_XOR_MULT_DOSStub_6770 {
  strings:
    $key_6770 = { 33 18 [2] 47 00 [2] 00 02 [2] 47 13 [2] 09 1f [2] 05 15 [2] 12 1e [2] 09 50 [2] 34 }

  condition:
    any of them
}