rule TTP_XOR_MULT_DOSStub_3c75 {
  strings:
    $key_3c75 = { 68 1d [2] 1c 05 [2] 5b 07 [2] 1c 16 [2] 52 1a [2] 5e 10 [2] 49 1b [2] 52 55 [2] 6f }

  condition:
    any of them
}