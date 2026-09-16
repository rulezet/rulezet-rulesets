rule TTP_XOR_MULT_DOSStub_1f18 {
  strings:
    $key_1f18 = { 4b 70 [2] 3f 68 [2] 78 6a [2] 3f 7b [2] 71 77 [2] 7d 7d [2] 6a 76 [2] 71 38 [2] 4c }

  condition:
    any of them
}