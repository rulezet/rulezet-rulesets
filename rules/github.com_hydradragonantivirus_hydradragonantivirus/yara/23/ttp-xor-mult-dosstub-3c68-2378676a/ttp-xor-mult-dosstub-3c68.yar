rule TTP_XOR_MULT_DOSStub_3c68 {
  strings:
    $key_3c68 = { 68 00 [2] 1c 18 [2] 5b 1a [2] 1c 0b [2] 52 07 [2] 5e 0d [2] 49 06 [2] 52 48 [2] 6f }

  condition:
    any of them
}