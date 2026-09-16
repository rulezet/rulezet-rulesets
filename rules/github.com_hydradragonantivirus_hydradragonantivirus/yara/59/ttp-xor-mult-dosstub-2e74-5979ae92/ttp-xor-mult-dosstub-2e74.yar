rule TTP_XOR_MULT_DOSStub_2e74 {
  strings:
    $key_2e74 = { 7a 1c [2] 0e 04 [2] 49 06 [2] 0e 17 [2] 40 1b [2] 4c 11 [2] 5b 1a [2] 40 54 [2] 7d }

  condition:
    any of them
}