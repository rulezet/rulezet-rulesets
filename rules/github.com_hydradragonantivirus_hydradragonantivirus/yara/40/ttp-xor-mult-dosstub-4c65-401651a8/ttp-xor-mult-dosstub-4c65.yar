rule TTP_XOR_MULT_DOSStub_4c65 {
  strings:
    $key_4c65 = { 18 0d [2] 6c 15 [2] 2b 17 [2] 6c 06 [2] 22 0a [2] 2e 00 [2] 39 0b [2] 22 45 [2] 1f }

  condition:
    any of them
}