rule TTP_XOR_MULT_DOSStub_2236 {
  strings:
    $key_2236 = { 76 5e [2] 02 46 [2] 45 44 [2] 02 55 [2] 4c 59 [2] 40 53 [2] 57 58 [2] 4c 16 [2] 71 }

  condition:
    any of them
}