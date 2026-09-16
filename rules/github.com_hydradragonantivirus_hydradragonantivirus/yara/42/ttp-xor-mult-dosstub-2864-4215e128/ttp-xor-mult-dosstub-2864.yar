rule TTP_XOR_MULT_DOSStub_2864 {
  strings:
    $key_2864 = { 7c 0c [2] 08 14 [2] 4f 16 [2] 08 07 [2] 46 0b [2] 4a 01 [2] 5d 0a [2] 46 44 [2] 7b }

  condition:
    any of them
}