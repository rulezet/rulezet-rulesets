rule TTP_XOR_MULT_DOSStub_0076 {
  strings:
    $key_0076 = { 54 1e [2] 20 06 [2] 67 04 [2] 20 15 [2] 6e 19 [2] 62 13 [2] 75 18 [2] 6e 56 [2] 53 }

  condition:
    any of them
}