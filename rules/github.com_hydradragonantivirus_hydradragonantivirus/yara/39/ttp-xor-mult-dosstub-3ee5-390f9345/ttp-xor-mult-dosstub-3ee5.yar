rule TTP_XOR_MULT_DOSStub_3ee5 {
  strings:
    $key_3ee5 = { 6a 8d [2] 1e 95 [2] 59 97 [2] 1e 86 [2] 50 8a [2] 5c 80 [2] 4b 8b [2] 50 c5 [2] 6d }

  condition:
    any of them
}