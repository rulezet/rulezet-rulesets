rule TTP_XOR_MULT_DOSStub_2869 {
  strings:
    $key_2869 = { 7c 01 [2] 08 19 [2] 4f 1b [2] 08 0a [2] 46 06 [2] 4a 0c [2] 5d 07 [2] 46 49 [2] 7b }

  condition:
    any of them
}