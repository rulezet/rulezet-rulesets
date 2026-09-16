rule TTP_XOR_MULT_DOSStub_3256 {
  strings:
    $key_3256 = { 66 3e [2] 12 26 [2] 55 24 [2] 12 35 [2] 5c 39 [2] 50 33 [2] 47 38 [2] 5c 76 [2] 61 }

  condition:
    any of them
}