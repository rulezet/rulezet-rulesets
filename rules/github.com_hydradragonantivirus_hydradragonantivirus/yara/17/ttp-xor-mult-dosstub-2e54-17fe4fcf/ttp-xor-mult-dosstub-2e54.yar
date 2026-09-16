rule TTP_XOR_MULT_DOSStub_2e54 {
  strings:
    $key_2e54 = { 7a 3c [2] 0e 24 [2] 49 26 [2] 0e 37 [2] 40 3b [2] 4c 31 [2] 5b 3a [2] 40 74 [2] 7d }

  condition:
    any of them
}