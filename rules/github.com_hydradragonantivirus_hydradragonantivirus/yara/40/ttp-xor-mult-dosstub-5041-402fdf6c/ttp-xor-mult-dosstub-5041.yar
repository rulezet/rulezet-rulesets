rule TTP_XOR_MULT_DOSStub_5041 {
  strings:
    $key_5041 = { 04 29 [2] 70 31 [2] 37 33 [2] 70 22 [2] 3e 2e [2] 32 24 [2] 25 2f [2] 3e 61 [2] 03 }

  condition:
    any of them
}