rule TTP_XOR_MULT_DOSStub_3667 {
  strings:
    $key_3667 = { 62 0f [2] 16 17 [2] 51 15 [2] 16 04 [2] 58 08 [2] 54 02 [2] 43 09 [2] 58 47 [2] 65 }

  condition:
    any of them
}