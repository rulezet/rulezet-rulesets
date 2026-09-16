rule TTP_XOR_MULT_DOSStub_4411 {
  strings:
    $key_4411 = { 10 79 [2] 64 61 [2] 23 63 [2] 64 72 [2] 2a 7e [2] 26 74 [2] 31 7f [2] 2a 31 [2] 17 }

  condition:
    any of them
}