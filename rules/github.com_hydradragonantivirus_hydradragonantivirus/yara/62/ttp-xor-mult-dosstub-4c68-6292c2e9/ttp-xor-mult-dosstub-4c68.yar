rule TTP_XOR_MULT_DOSStub_4c68 {
  strings:
    $key_4c68 = { 18 00 [2] 6c 18 [2] 2b 1a [2] 6c 0b [2] 22 07 [2] 2e 0d [2] 39 06 [2] 22 48 [2] 1f }

  condition:
    any of them
}