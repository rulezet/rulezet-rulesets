rule TTP_XOR_MULT_DOSStub_4c76 {
  strings:
    $key_4c76 = { 18 1e [2] 6c 06 [2] 2b 04 [2] 6c 15 [2] 22 19 [2] 2e 13 [2] 39 18 [2] 22 56 [2] 1f }

  condition:
    any of them
}