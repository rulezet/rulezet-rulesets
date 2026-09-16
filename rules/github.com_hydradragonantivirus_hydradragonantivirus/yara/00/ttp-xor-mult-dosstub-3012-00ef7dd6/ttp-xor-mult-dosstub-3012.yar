rule TTP_XOR_MULT_DOSStub_3012 {
  strings:
    $key_3012 = { 64 7a [2] 10 62 [2] 57 60 [2] 10 71 [2] 5e 7d [2] 52 77 [2] 45 7c [2] 5e 32 [2] 63 }

  condition:
    any of them
}