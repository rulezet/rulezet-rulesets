rule TTP_XOR_MULT_DOSStub_5d12 {
  strings:
    $key_5d12 = { 09 7a [2] 7d 62 [2] 3a 60 [2] 7d 71 [2] 33 7d [2] 3f 77 [2] 28 7c [2] 33 32 [2] 0e }

  condition:
    any of them
}