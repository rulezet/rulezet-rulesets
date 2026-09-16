rule TTP_XOR_MULT_DOSStub_1361 {
  strings:
    $key_1361 = { 47 09 [2] 33 11 [2] 74 13 [2] 33 02 [2] 7d 0e [2] 71 04 [2] 66 0f [2] 7d 41 [2] 40 }

  condition:
    any of them
}