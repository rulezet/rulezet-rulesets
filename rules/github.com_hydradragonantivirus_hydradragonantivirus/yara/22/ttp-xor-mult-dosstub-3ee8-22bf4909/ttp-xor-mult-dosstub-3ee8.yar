rule TTP_XOR_MULT_DOSStub_3ee8 {
  strings:
    $key_3ee8 = { 6a 80 [2] 1e 98 [2] 59 9a [2] 1e 8b [2] 50 87 [2] 5c 8d [2] 4b 86 [2] 50 c8 [2] 6d }

  condition:
    any of them
}