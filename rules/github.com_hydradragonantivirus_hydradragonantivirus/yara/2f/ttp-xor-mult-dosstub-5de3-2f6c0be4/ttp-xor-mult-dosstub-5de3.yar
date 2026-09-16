rule TTP_XOR_MULT_DOSStub_5de3 {
  strings:
    $key_5de3 = { 09 8b [2] 7d 93 [2] 3a 91 [2] 7d 80 [2] 33 8c [2] 3f 86 [2] 28 8d [2] 33 c3 [2] 0e }

  condition:
    any of them
}