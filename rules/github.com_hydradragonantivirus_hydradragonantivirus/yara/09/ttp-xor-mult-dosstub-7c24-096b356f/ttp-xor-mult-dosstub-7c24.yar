rule TTP_XOR_MULT_DOSStub_7c24 {
  strings:
    $key_7c24 = { 28 4c [2] 5c 54 [2] 1b 56 [2] 5c 47 [2] 12 4b [2] 1e 41 [2] 09 4a [2] 12 04 [2] 2f }

  condition:
    any of them
}