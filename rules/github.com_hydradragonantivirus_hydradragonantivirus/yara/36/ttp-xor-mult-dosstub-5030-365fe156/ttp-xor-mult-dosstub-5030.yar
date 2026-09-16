rule TTP_XOR_MULT_DOSStub_5030 {
  strings:
    $key_5030 = { 04 58 [2] 70 40 [2] 37 42 [2] 70 53 [2] 3e 5f [2] 32 55 [2] 25 5e [2] 3e 10 [2] 03 }

  condition:
    any of them
}