rule TTP_XOR_MULT_DOSStub_7206 {
  strings:
    $key_7206 = { 26 6e [2] 52 76 [2] 15 74 [2] 52 65 [2] 1c 69 [2] 10 63 [2] 07 68 [2] 1c 26 [2] 21 }

  condition:
    any of them
}