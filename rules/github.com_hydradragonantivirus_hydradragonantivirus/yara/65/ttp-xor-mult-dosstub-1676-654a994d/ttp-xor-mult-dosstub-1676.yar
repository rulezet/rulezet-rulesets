rule TTP_XOR_MULT_DOSStub_1676 {
  strings:
    $key_1676 = { 42 1e [2] 36 06 [2] 71 04 [2] 36 15 [2] 78 19 [2] 74 13 [2] 63 18 [2] 78 56 [2] 45 }

  condition:
    any of them
}