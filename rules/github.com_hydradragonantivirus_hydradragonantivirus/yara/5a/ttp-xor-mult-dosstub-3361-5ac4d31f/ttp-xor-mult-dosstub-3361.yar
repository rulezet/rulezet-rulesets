rule TTP_XOR_MULT_DOSStub_3361 {
  strings:
    $key_3361 = { 67 09 [2] 13 11 [2] 54 13 [2] 13 02 [2] 5d 0e [2] 51 04 [2] 46 0f [2] 5d 41 [2] 60 }

  condition:
    any of them
}