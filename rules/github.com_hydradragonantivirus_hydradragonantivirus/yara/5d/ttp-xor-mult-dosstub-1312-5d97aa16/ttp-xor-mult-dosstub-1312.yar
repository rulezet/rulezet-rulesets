rule TTP_XOR_MULT_DOSStub_1312 {
  strings:
    $key_1312 = { 47 7a [2] 33 62 [2] 74 60 [2] 33 71 [2] 7d 7d [2] 71 77 [2] 66 7c [2] 7d 32 [2] 40 }

  condition:
    any of them
}