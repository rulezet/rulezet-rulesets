rule TTP_XOR_MULT_DOSStub_1f14 {
  strings:
    $key_1f14 = { 4b 7c [2] 3f 64 [2] 78 66 [2] 3f 77 [2] 71 7b [2] 7d 71 [2] 6a 7a [2] 71 34 [2] 4c }

  condition:
    any of them
}