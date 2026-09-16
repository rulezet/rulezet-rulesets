rule TTP_XOR_MULT_DOSStub_37f0 {
  strings:
    $key_37f0 = { 63 98 [2] 17 80 [2] 50 82 [2] 17 93 [2] 59 9f [2] 55 95 [2] 42 9e [2] 59 d0 [2] 64 }

  condition:
    any of them
}