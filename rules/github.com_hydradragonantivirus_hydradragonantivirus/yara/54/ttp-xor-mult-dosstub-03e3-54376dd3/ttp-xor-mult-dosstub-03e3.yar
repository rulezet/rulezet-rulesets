rule TTP_XOR_MULT_DOSStub_03e3 {
  strings:
    $key_03e3 = { 57 8b [2] 23 93 [2] 64 91 [2] 23 80 [2] 6d 8c [2] 61 86 [2] 76 8d [2] 6d c3 [2] 50 }

  condition:
    any of them
}