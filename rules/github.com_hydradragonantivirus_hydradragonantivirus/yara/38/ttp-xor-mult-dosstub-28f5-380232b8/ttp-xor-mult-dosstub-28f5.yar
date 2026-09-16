rule TTP_XOR_MULT_DOSStub_28f5 {
  strings:
    $key_28f5 = { 7c 9d [2] 08 85 [2] 4f 87 [2] 08 96 [2] 46 9a [2] 4a 90 [2] 5d 9b [2] 46 d5 [2] 7b }

  condition:
    any of them
}