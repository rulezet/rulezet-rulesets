rule TTP_XOR_MULT_DOSStub_2e68 {
  strings:
    $key_2e68 = { 7a 00 [2] 0e 18 [2] 49 1a [2] 0e 0b [2] 40 07 [2] 4c 0d [2] 5b 06 [2] 40 48 [2] 7d }

  condition:
    any of them
}