rule TTP_XOR_MULT_DOSStub_2e72 {
  strings:
    $key_2e72 = { 7a 1a [2] 0e 02 [2] 49 00 [2] 0e 11 [2] 40 1d [2] 4c 17 [2] 5b 1c [2] 40 52 [2] 7d }

  condition:
    any of them
}