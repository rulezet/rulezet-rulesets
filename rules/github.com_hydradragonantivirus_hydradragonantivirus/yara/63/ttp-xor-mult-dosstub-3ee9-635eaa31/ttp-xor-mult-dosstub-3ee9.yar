rule TTP_XOR_MULT_DOSStub_3ee9 {
  strings:
    $key_3ee9 = { 6a 81 [2] 1e 99 [2] 59 9b [2] 1e 8a [2] 50 86 [2] 5c 8c [2] 4b 87 [2] 50 c9 [2] 6d }

  condition:
    any of them
}