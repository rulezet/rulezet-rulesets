rule TTP_XOR_MULT_DOSStub_50e7 {
  strings:
    $key_50e7 = { 04 8f [2] 70 97 [2] 37 95 [2] 70 84 [2] 3e 88 [2] 32 82 [2] 25 89 [2] 3e c7 [2] 03 }

  condition:
    any of them
}