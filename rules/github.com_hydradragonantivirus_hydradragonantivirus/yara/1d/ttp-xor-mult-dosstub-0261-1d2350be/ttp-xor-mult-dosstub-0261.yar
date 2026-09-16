rule TTP_XOR_MULT_DOSStub_0261 {
  strings:
    $key_0261 = { 56 09 [2] 22 11 [2] 65 13 [2] 22 02 [2] 6c 0e [2] 60 04 [2] 77 0f [2] 6c 41 [2] 51 }

  condition:
    any of them
}