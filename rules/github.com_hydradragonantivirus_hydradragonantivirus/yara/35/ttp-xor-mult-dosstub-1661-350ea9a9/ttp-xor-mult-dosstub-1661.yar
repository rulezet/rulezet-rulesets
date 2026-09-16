rule TTP_XOR_MULT_DOSStub_1661 {
  strings:
    $key_1661 = { 42 09 [2] 36 11 [2] 71 13 [2] 36 02 [2] 78 0e [2] 74 04 [2] 63 0f [2] 78 41 [2] 45 }

  condition:
    any of them
}