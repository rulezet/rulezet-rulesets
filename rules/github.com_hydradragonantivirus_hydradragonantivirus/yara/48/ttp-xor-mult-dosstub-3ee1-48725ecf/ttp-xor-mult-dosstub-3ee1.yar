rule TTP_XOR_MULT_DOSStub_3ee1 {
  strings:
    $key_3ee1 = { 6a 89 [2] 1e 91 [2] 59 93 [2] 1e 82 [2] 50 8e [2] 5c 84 [2] 4b 8f [2] 50 c1 [2] 6d }

  condition:
    any of them
}