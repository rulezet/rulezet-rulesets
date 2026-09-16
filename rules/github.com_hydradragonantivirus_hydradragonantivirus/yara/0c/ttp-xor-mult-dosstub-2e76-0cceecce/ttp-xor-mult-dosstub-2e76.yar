rule TTP_XOR_MULT_DOSStub_2e76 {
  strings:
    $key_2e76 = { 7a 1e [2] 0e 06 [2] 49 04 [2] 0e 15 [2] 40 19 [2] 4c 13 [2] 5b 18 [2] 40 56 [2] 7d }

  condition:
    any of them
}