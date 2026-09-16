rule TTP_XOR_MULT_DOSStub_1267 {
  strings:
    $key_1267 = { 46 0f [2] 32 17 [2] 75 15 [2] 32 04 [2] 7c 08 [2] 70 02 [2] 67 09 [2] 7c 47 [2] 41 }

  condition:
    any of them
}