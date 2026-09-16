rule TTP_XOR_MULT_DOSStub_2312 {
  strings:
    $key_2312 = { 77 7a [2] 03 62 [2] 44 60 [2] 03 71 [2] 4d 7d [2] 41 77 [2] 56 7c [2] 4d 32 [2] 70 }

  condition:
    any of them
}