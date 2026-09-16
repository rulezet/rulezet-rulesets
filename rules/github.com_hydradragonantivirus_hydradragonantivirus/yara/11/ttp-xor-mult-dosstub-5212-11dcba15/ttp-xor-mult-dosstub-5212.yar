rule TTP_XOR_MULT_DOSStub_5212 {
  strings:
    $key_5212 = { 06 7a [2] 72 62 [2] 35 60 [2] 72 71 [2] 3c 7d [2] 30 77 [2] 27 7c [2] 3c 32 [2] 01 }

  condition:
    any of them
}