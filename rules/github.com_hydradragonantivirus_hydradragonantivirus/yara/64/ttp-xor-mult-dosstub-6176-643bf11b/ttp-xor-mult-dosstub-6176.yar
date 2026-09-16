rule TTP_XOR_MULT_DOSStub_6176 {
  strings:
    $key_6176 = { 35 1e [2] 41 06 [2] 06 04 [2] 41 15 [2] 0f 19 [2] 03 13 [2] 14 18 [2] 0f 56 [2] 32 }

  condition:
    any of them
}