rule TTP_XOR_MULT_DOSStub_3c12 {
  strings:
    $key_3c12 = { 68 7a [2] 1c 62 [2] 5b 60 [2] 1c 71 [2] 52 7d [2] 5e 77 [2] 49 7c [2] 52 32 [2] 6f }

  condition:
    any of them
}