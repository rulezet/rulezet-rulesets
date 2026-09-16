rule TTP_XOR_MULT_DOSStub_28e8 {
  strings:
    $key_28e8 = { 7c 80 [2] 08 98 [2] 4f 9a [2] 08 8b [2] 46 87 [2] 4a 8d [2] 5d 86 [2] 46 c8 [2] 7b }

  condition:
    any of them
}