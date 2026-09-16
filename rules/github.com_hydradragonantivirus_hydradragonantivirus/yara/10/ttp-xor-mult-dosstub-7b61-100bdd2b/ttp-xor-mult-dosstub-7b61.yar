rule TTP_XOR_MULT_DOSStub_7b61 {
  strings:
    $key_7b61 = { 2f 09 [2] 5b 11 [2] 1c 13 [2] 5b 02 [2] 15 0e [2] 19 04 [2] 0e 0f [2] 15 41 [2] 28 }

  condition:
    any of them
}