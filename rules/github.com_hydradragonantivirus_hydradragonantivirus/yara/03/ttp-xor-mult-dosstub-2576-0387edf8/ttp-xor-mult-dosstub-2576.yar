rule TTP_XOR_MULT_DOSStub_2576 {
  strings:
    $key_2576 = { 71 1e [2] 05 06 [2] 42 04 [2] 05 15 [2] 4b 19 [2] 47 13 [2] 50 18 [2] 4b 56 [2] 76 }

  condition:
    any of them
}