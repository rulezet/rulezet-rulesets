rule TTP_XOR_MULT_DOSStub_3a12 {
  strings:
    $key_3a12 = { 6e 7a [2] 1a 62 [2] 5d 60 [2] 1a 71 [2] 54 7d [2] 58 77 [2] 4f 7c [2] 54 32 [2] 69 }

  condition:
    any of them
}