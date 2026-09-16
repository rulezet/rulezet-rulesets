rule TTP_XOR_MULT_DOSStub_2834 {
  strings:
    $key_2834 = { 7c 5c [2] 08 44 [2] 4f 46 [2] 08 57 [2] 46 5b [2] 4a 51 [2] 5d 5a [2] 46 14 [2] 7b }

  condition:
    any of them
}