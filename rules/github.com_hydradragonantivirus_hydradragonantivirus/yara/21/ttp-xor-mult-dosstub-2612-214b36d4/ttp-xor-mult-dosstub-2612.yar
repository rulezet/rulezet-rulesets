rule TTP_XOR_MULT_DOSStub_2612 {
  strings:
    $key_2612 = { 72 7a [2] 06 62 [2] 41 60 [2] 06 71 [2] 48 7d [2] 44 77 [2] 53 7c [2] 48 32 [2] 75 }

  condition:
    any of them
}