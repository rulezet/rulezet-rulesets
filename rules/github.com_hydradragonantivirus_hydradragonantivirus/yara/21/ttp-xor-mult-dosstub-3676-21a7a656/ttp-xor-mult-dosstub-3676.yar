rule TTP_XOR_MULT_DOSStub_3676 {
  strings:
    $key_3676 = { 62 1e [2] 16 06 [2] 51 04 [2] 16 15 [2] 58 19 [2] 54 13 [2] 43 18 [2] 58 56 [2] 65 }

  condition:
    any of them
}