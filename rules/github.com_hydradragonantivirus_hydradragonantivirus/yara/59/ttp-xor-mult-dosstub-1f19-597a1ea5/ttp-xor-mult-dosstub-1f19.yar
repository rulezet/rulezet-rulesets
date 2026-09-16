rule TTP_XOR_MULT_DOSStub_1f19 {
  strings:
    $key_1f19 = { 4b 71 [2] 3f 69 [2] 78 6b [2] 3f 7a [2] 71 76 [2] 7d 7c [2] 6a 77 [2] 71 39 [2] 4c }

  condition:
    any of them
}