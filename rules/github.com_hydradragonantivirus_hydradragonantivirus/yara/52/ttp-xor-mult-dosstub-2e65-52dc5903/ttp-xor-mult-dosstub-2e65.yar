rule TTP_XOR_MULT_DOSStub_2e65 {
  strings:
    $key_2e65 = { 7a 0d [2] 0e 15 [2] 49 17 [2] 0e 06 [2] 40 0a [2] 4c 00 [2] 5b 0b [2] 40 45 [2] 7d }

  condition:
    any of them
}