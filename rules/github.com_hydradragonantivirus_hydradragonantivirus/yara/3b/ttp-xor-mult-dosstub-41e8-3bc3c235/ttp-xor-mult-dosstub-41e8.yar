rule TTP_XOR_MULT_DOSStub_41e8 {
  strings:
    $key_41e8 = { 15 80 [2] 61 98 [2] 26 9a [2] 61 8b [2] 2f 87 [2] 23 8d [2] 34 86 [2] 2f c8 [2] 12 }

  condition:
    any of them
}