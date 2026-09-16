rule TTP_XOR_MULT_DOSStub_2845 {
  strings:
    $key_2845 = { 7c 2d [2] 08 35 [2] 4f 37 [2] 08 26 [2] 46 2a [2] 4a 20 [2] 5d 2b [2] 46 65 [2] 7b }

  condition:
    any of them
}