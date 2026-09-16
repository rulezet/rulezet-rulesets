rule TTP_XOR_MULT_DOSStub_3312 {
  strings:
    $key_3312 = { 67 7a [2] 13 62 [2] 54 60 [2] 13 71 [2] 5d 7d [2] 51 77 [2] 46 7c [2] 5d 32 [2] 60 }

  condition:
    any of them
}