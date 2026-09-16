rule TTP_XOR_MULT_DOSStub_4767 {
  strings:
    $key_4767 = { 13 0f [2] 67 17 [2] 20 15 [2] 67 04 [2] 29 08 [2] 25 02 [2] 32 09 [2] 29 47 [2] 14 }

  condition:
    any of them
}