rule TTP_XOR_MULT_DOSStub_2825 {
  strings:
    $key_2825 = { 7c 4d [2] 08 55 [2] 4f 57 [2] 08 46 [2] 46 4a [2] 4a 40 [2] 5d 4b [2] 46 05 [2] 7b }

  condition:
    any of them
}