rule TTP_XOR_MULT_DOSStub_3041 {
  strings:
    $key_3041 = { 64 29 [2] 10 31 [2] 57 33 [2] 10 22 [2] 5e 2e [2] 52 24 [2] 45 2f [2] 5e 61 [2] 63 }

  condition:
    any of them
}