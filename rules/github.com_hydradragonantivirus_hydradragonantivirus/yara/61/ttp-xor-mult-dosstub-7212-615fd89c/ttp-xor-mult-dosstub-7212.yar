rule TTP_XOR_MULT_DOSStub_7212 {
  strings:
    $key_7212 = { 26 7a [2] 52 62 [2] 15 60 [2] 52 71 [2] 1c 7d [2] 10 77 [2] 07 7c [2] 1c 32 [2] 21 }

  condition:
    any of them
}