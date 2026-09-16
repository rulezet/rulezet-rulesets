rule TTP_XOR_MULT_DOSStub_7260 {
  strings:
    $key_7260 = { 26 08 [2] 52 10 [2] 15 12 [2] 52 03 [2] 1c 0f [2] 10 05 [2] 07 0e [2] 1c 40 [2] 21 }

  condition:
    any of them
}