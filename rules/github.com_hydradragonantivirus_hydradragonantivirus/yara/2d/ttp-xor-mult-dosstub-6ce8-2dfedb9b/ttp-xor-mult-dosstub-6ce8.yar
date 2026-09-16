rule TTP_XOR_MULT_DOSStub_6ce8 {
  strings:
    $key_6ce8 = { 38 80 [2] 4c 98 [2] 0b 9a [2] 4c 8b [2] 02 87 [2] 0e 8d [2] 19 86 [2] 02 c8 [2] 3f }

  condition:
    any of them
}