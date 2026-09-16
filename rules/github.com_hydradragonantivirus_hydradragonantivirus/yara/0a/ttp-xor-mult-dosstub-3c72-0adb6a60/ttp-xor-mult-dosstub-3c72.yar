rule TTP_XOR_MULT_DOSStub_3c72 {
  strings:
    $key_3c72 = { 68 1a [2] 1c 02 [2] 5b 00 [2] 1c 11 [2] 52 1d [2] 5e 17 [2] 49 1c [2] 52 52 [2] 6f }

  condition:
    any of them
}