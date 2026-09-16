rule TTP_XOR_MULT_DOSStub_2824 {
  strings:
    $key_2824 = { 7c 4c [2] 08 54 [2] 4f 56 [2] 08 47 [2] 46 4b [2] 4a 41 [2] 5d 4a [2] 46 04 [2] 7b }

  condition:
    any of them
}