rule TTP_XOR_MULT_DOSStub_7250 {
  strings:
    $key_7250 = { 26 38 [2] 52 20 [2] 15 22 [2] 52 33 [2] 1c 3f [2] 10 35 [2] 07 3e [2] 1c 70 [2] 21 }

  condition:
    any of them
}