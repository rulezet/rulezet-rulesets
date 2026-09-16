rule TTP_XOR_MULT_DOSStub_2828 {
  strings:
    $key_2828 = { 7c 40 [2] 08 58 [2] 4f 5a [2] 08 4b [2] 46 47 [2] 4a 4d [2] 5d 46 [2] 46 08 [2] 7b }

  condition:
    any of them
}