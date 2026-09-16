rule TTP_XOR_MULT_DOSStub_2b56 {
  strings:
    $key_2b56 = { 7f 3e [2] 0b 26 [2] 4c 24 [2] 0b 35 [2] 45 39 [2] 49 33 [2] 5e 38 [2] 45 76 [2] 78 }

  condition:
    any of them
}