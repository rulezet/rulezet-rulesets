rule TTP_XOR_MULT_DOSStub_0676 {
  strings:
    $key_0676 = { 52 1e [2] 26 06 [2] 61 04 [2] 26 15 [2] 68 19 [2] 64 13 [2] 73 18 [2] 68 56 [2] 55 }

  condition:
    any of them
}