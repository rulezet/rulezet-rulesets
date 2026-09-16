rule TTP_XOR_MULT_DOSStub_7270 {
  strings:
    $key_7270 = { 26 18 [2] 52 00 [2] 15 02 [2] 52 13 [2] 1c 1f [2] 10 15 [2] 07 1e [2] 1c 50 [2] 21 }

  condition:
    any of them
}