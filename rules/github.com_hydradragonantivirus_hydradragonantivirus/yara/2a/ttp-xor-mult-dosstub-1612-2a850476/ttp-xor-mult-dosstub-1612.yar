rule TTP_XOR_MULT_DOSStub_1612 {
  strings:
    $key_1612 = { 42 7a [2] 36 62 [2] 71 60 [2] 36 71 [2] 78 7d [2] 74 77 [2] 63 7c [2] 78 32 [2] 45 }

  condition:
    any of them
}