rule TTP_XOR_MULT_DOSStub_6261 {
  strings:
    $key_6261 = { 36 09 [2] 42 11 [2] 05 13 [2] 42 02 [2] 0c 0e [2] 00 04 [2] 17 0f [2] 0c 41 [2] 31 }

  condition:
    any of them
}