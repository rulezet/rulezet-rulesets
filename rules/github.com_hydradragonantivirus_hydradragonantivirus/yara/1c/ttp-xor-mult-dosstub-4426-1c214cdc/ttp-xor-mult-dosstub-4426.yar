rule TTP_XOR_MULT_DOSStub_4426 {
  strings:
    $key_4426 = { 10 4e [2] 64 56 [2] 23 54 [2] 64 45 [2] 2a 49 [2] 26 43 [2] 31 48 [2] 2a 06 [2] 17 }

  condition:
    any of them
}