rule TTP_XOR_MULT_DOSStub_2161 {
  strings:
    $key_2161 = { 75 09 [2] 01 11 [2] 46 13 [2] 01 02 [2] 4f 0e [2] 43 04 [2] 54 0f [2] 4f 41 [2] 72 }

  condition:
    any of them
}