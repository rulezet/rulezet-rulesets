rule TTP_XOR_MULT_DOSStub_3ee6 {
  strings:
    $key_3ee6 = { 6a 8e [2] 1e 96 [2] 59 94 [2] 1e 85 [2] 50 89 [2] 5c 83 [2] 4b 88 [2] 50 c6 [2] 6d }

  condition:
    any of them
}