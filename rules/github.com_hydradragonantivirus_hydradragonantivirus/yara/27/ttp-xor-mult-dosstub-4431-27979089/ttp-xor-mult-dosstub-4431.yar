rule TTP_XOR_MULT_DOSStub_4431 {
  strings:
    $key_4431 = { 10 59 [2] 64 41 [2] 23 43 [2] 64 52 [2] 2a 5e [2] 26 54 [2] 31 5f [2] 2a 11 [2] 17 }

  condition:
    any of them
}