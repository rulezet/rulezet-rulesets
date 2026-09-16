rule TTP_XOR_MULT_DOSStub_4ae3 {
  strings:
    $key_4ae3 = { 1e 8b [2] 6a 93 [2] 2d 91 [2] 6a 80 [2] 24 8c [2] 28 86 [2] 3f 8d [2] 24 c3 [2] 19 }

  condition:
    any of them
}