rule TTP_XOR_MULT_DOSStub_1220 {
  strings:
    $key_1220 = { 46 48 [2] 32 50 [2] 75 52 [2] 32 43 [2] 7c 4f [2] 70 45 [2] 67 4e [2] 7c 00 [2] 41 }

  condition:
    any of them
}