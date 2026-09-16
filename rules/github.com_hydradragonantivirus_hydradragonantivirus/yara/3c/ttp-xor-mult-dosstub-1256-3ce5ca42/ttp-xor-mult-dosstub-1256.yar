rule TTP_XOR_MULT_DOSStub_1256 {
  strings:
    $key_1256 = { 46 3e [2] 32 26 [2] 75 24 [2] 32 35 [2] 7c 39 [2] 70 33 [2] 67 38 [2] 7c 76 [2] 41 }

  condition:
    any of them
}