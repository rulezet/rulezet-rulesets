rule TTP_XOR_MULT_DOSStub_7661 {
  strings:
    $key_7661 = { 22 09 [2] 56 11 [2] 11 13 [2] 56 02 [2] 18 0e [2] 14 04 [2] 03 0f [2] 18 41 [2] 25 }

  condition:
    any of them
}