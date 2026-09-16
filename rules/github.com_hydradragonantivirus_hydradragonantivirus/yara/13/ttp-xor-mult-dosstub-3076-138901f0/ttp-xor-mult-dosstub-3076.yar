rule TTP_XOR_MULT_DOSStub_3076 {
  strings:
    $key_3076 = { 64 1e [2] 10 06 [2] 57 04 [2] 10 15 [2] 5e 19 [2] 52 13 [2] 45 18 [2] 5e 56 [2] 63 }

  condition:
    any of them
}