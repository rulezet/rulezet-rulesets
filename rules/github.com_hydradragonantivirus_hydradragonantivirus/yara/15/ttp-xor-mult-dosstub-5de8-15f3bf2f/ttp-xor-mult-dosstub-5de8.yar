rule TTP_XOR_MULT_DOSStub_5de8 {
  strings:
    $key_5de8 = { 09 80 [2] 7d 98 [2] 3a 9a [2] 7d 8b [2] 33 87 [2] 3f 8d [2] 28 86 [2] 33 c8 [2] 0e }

  condition:
    any of them
}