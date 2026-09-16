rule TTP_XOR_MULT_DOSStub_7367 {
  strings:
    $key_7367 = { 27 0f [2] 53 17 [2] 14 15 [2] 53 04 [2] 1d 08 [2] 11 02 [2] 06 09 [2] 1d 47 [2] 20 }

  condition:
    any of them
}