rule TTP_XOR_MULT_DOSStub_0512 {
  strings:
    $key_0512 = { 51 7a [2] 25 62 [2] 62 60 [2] 25 71 [2] 6b 7d [2] 67 77 [2] 70 7c [2] 6b 32 [2] 56 }

  condition:
    any of them
}