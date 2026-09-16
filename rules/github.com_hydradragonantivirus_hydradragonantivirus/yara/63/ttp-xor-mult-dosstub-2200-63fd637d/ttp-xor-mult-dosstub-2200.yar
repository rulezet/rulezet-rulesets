rule TTP_XOR_MULT_DOSStub_2200 {
  strings:
    $key_2200 = { 76 68 [2] 02 70 [2] 45 72 [2] 02 63 [2] 4c 6f [2] 40 65 [2] 57 6e [2] 4c 20 [2] 71 }

  condition:
    any of them
}