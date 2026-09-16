rule TTP_XOR_MULT_DOSStub_370c {
  strings:
    $key_370c = { 63 64 [2] 17 7c [2] 50 7e [2] 17 6f [2] 59 63 [2] 55 69 [2] 42 62 [2] 59 2c [2] 64 }

  condition:
    any of them
}