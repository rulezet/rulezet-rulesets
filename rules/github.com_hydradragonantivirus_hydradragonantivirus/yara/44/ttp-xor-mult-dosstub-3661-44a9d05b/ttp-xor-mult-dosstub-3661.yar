rule TTP_XOR_MULT_DOSStub_3661 {
  strings:
    $key_3661 = { 62 09 [2] 16 11 [2] 51 13 [2] 16 02 [2] 58 0e [2] 54 04 [2] 43 0f [2] 58 41 [2] 65 }

  condition:
    any of them
}