rule TTP_XOR_MULT_DOSStub_3f14 {
  strings:
    $key_3f14 = { 6b 7c [2] 1f 64 [2] 58 66 [2] 1f 77 [2] 51 7b [2] 5d 71 [2] 4a 7a [2] 51 34 [2] 6c }

  condition:
    any of them
}