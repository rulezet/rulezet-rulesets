rule TTP_XOR_MULT_DOSStub_5839 {
  strings:
    $key_5839 = { 0c 51 [2] 78 49 [2] 3f 4b [2] 78 5a [2] 36 56 [2] 3a 5c [2] 2d 57 [2] 36 19 [2] 0b }

  condition:
    any of them
}