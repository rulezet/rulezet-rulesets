rule TTP_XOR_MULT_DOSStub_6c12 {
  strings:
    $key_6c12 = { 38 7a [2] 4c 62 [2] 0b 60 [2] 4c 71 [2] 02 7d [2] 0e 77 [2] 19 7c [2] 02 32 [2] 3f }

  condition:
    any of them
}