rule TTP_XOR_MULT_DOSStub_2661 {
  strings:
    $key_2661 = { 72 09 [2] 06 11 [2] 41 13 [2] 06 02 [2] 48 0e [2] 44 04 [2] 53 0f [2] 48 41 [2] 75 }

  condition:
    any of them
}