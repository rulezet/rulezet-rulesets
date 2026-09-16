rule TTP_XOR_MULT_DOSStub_7176 {
  strings:
    $key_7176 = { 25 1e [2] 51 06 [2] 16 04 [2] 51 15 [2] 1f 19 [2] 13 13 [2] 04 18 [2] 1f 56 [2] 22 }

  condition:
    any of them
}