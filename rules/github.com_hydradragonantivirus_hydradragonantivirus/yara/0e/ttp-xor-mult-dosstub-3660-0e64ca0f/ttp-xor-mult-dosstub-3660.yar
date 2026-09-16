rule TTP_XOR_MULT_DOSStub_3660 {
  strings:
    $key_3660 = { 62 08 [2] 16 10 [2] 51 12 [2] 16 03 [2] 58 0f [2] 54 05 [2] 43 0e [2] 58 40 [2] 65 }

  condition:
    any of them
}