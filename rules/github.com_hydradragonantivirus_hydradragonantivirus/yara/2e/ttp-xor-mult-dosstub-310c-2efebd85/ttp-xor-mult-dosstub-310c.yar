rule TTP_XOR_MULT_DOSStub_310c {
  strings:
    $key_310c = { 65 64 [2] 11 7c [2] 56 7e [2] 11 6f [2] 5f 63 [2] 53 69 [2] 44 62 [2] 5f 2c [2] 62 }

  condition:
    any of them
}