rule TTP_XOR_MULT_DOSStub_2877 {
  strings:
    $key_2877 = { 7c 1f [2] 08 07 [2] 4f 05 [2] 08 14 [2] 46 18 [2] 4a 12 [2] 5d 19 [2] 46 57 [2] 7b }

  condition:
    any of them
}