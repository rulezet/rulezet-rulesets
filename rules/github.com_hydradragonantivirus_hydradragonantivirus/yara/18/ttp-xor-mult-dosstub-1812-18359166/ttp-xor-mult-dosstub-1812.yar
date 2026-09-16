rule TTP_XOR_MULT_DOSStub_1812 {
  strings:
    $key_1812 = { 4c 7a [2] 38 62 [2] 7f 60 [2] 38 71 [2] 76 7d [2] 7a 77 [2] 6d 7c [2] 76 32 [2] 4b }

  condition:
    any of them
}