rule TTP_XOR_MULT_DOSStub_7130 {
  strings:
    $key_7130 = { 25 58 [2] 51 40 [2] 16 42 [2] 51 53 [2] 1f 5f [2] 13 55 [2] 04 5e [2] 1f 10 [2] 22 }

  condition:
    any of them
}