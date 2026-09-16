rule TTP_XOR_MULT_DOSStub_2879 {
  strings:
    $key_2879 = { 7c 11 [2] 08 09 [2] 4f 0b [2] 08 1a [2] 46 16 [2] 4a 1c [2] 5d 17 [2] 46 59 [2] 7b }

  condition:
    any of them
}