rule TTP_XOR_MULT_DOSStub_3ee4 {
  strings:
    $key_3ee4 = { 6a 8c [2] 1e 94 [2] 59 96 [2] 1e 87 [2] 50 8b [2] 5c 81 [2] 4b 8a [2] 50 c4 [2] 6d }

  condition:
    any of them
}