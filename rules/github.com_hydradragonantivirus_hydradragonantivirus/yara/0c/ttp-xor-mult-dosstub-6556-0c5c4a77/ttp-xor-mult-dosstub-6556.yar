rule TTP_XOR_MULT_DOSStub_6556 {
  strings:
    $key_6556 = { 31 3e [2] 45 26 [2] 02 24 [2] 45 35 [2] 0b 39 [2] 07 33 [2] 10 38 [2] 0b 76 [2] 36 }

  condition:
    any of them
}