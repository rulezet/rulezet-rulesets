rule TTP_XOR_MULT_DOSStub_3c62 {
  strings:
    $key_3c62 = { 68 0a [2] 1c 12 [2] 5b 10 [2] 1c 01 [2] 52 0d [2] 5e 07 [2] 49 0c [2] 52 42 [2] 6f }

  condition:
    any of them
}