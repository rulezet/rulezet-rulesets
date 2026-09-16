rule TTP_XOR_MULT_DOSStub_2d12 {
  strings:
    $key_2d12 = { 79 7a [2] 0d 62 [2] 4a 60 [2] 0d 71 [2] 43 7d [2] 4f 77 [2] 58 7c [2] 43 32 [2] 7e }

  condition:
    any of them
}