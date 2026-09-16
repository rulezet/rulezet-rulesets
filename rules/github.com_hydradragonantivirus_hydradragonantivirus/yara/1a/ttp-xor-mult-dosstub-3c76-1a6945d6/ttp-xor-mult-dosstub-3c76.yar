rule TTP_XOR_MULT_DOSStub_3c76 {
  strings:
    $key_3c76 = { 68 1e [2] 1c 06 [2] 5b 04 [2] 1c 15 [2] 52 19 [2] 5e 13 [2] 49 18 [2] 52 56 [2] 6f }

  condition:
    any of them
}