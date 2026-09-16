rule TTP_XOR_MULT_DOSStub_4112 {
  strings:
    $key_4112 = { 15 7a [2] 61 62 [2] 26 60 [2] 61 71 [2] 2f 7d [2] 23 77 [2] 34 7c [2] 2f 32 [2] 12 }

  condition:
    any of them
}