rule TTP_XOR_MULT_DOSStub_2b76 {
  strings:
    $key_2b76 = { 7f 1e [2] 0b 06 [2] 4c 04 [2] 0b 15 [2] 45 19 [2] 49 13 [2] 5e 18 [2] 45 56 [2] 78 }

  condition:
    any of them
}