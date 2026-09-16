rule TTP_XOR_MULT_DOSStub_0b12 {
  strings:
    $key_0b12 = { 5f 7a [2] 2b 62 [2] 6c 60 [2] 2b 71 [2] 65 7d [2] 69 77 [2] 7e 7c [2] 65 32 [2] 58 }

  condition:
    any of them
}