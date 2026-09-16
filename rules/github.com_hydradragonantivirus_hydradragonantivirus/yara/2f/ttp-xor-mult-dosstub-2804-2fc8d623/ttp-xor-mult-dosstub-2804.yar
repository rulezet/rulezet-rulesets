rule TTP_XOR_MULT_DOSStub_2804 {
  strings:
    $key_2804 = { 7c 6c [2] 08 74 [2] 4f 76 [2] 08 67 [2] 46 6b [2] 4a 61 [2] 5d 6a [2] 46 24 [2] 7b }

  condition:
    any of them
}