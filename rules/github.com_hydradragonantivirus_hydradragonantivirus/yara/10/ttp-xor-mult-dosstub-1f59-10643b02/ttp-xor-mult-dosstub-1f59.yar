rule TTP_XOR_MULT_DOSStub_1f59 {
  strings:
    $key_1f59 = { 4b 31 [2] 3f 29 [2] 78 2b [2] 3f 3a [2] 71 36 [2] 7d 3c [2] 6a 37 [2] 71 79 [2] 4c }

  condition:
    any of them
}