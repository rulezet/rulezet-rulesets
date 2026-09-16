rule TTP_XOR_MULT_DOSStub_5de5 {
  strings:
    $key_5de5 = { 09 8d [2] 7d 95 [2] 3a 97 [2] 7d 86 [2] 33 8a [2] 3f 80 [2] 28 8b [2] 33 c5 [2] 0e }

  condition:
    any of them
}