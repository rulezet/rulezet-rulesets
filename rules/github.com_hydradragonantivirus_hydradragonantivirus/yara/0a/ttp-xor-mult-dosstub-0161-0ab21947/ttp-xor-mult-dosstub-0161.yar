rule TTP_XOR_MULT_DOSStub_0161 {
  strings:
    $key_0161 = { 55 09 [2] 21 11 [2] 66 13 [2] 21 02 [2] 6f 0e [2] 63 04 [2] 74 0f [2] 6f 41 [2] 52 }

  condition:
    any of them
}