rule TTP_XOR_MULT_DOSStub_1f12 {
  strings:
    $key_1f12 = { 4b 7a [2] 3f 62 [2] 78 60 [2] 3f 71 [2] 71 7d [2] 7d 77 [2] 6a 7c [2] 71 32 [2] 4c }

  condition:
    any of them
}