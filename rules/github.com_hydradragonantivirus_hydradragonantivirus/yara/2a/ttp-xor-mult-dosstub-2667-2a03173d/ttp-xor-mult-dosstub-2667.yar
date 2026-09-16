rule TTP_XOR_MULT_DOSStub_2667 {
  strings:
    $key_2667 = { 72 0f [2] 06 17 [2] 41 15 [2] 06 04 [2] 48 08 [2] 44 02 [2] 53 09 [2] 48 47 [2] 75 }

  condition:
    any of them
}