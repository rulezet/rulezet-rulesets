rule TTP_XOR_MULT_DOSStub_3612 {
  strings:
    $key_3612 = { 62 7a [2] 16 62 [2] 51 60 [2] 16 71 [2] 58 7d [2] 54 77 [2] 43 7c [2] 58 32 [2] 65 }

  condition:
    any of them
}