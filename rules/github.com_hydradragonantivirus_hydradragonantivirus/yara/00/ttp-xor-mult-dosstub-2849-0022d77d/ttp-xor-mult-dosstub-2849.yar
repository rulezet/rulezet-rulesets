rule TTP_XOR_MULT_DOSStub_2849 {
  strings:
    $key_2849 = { 7c 21 [2] 08 39 [2] 4f 3b [2] 08 2a [2] 46 26 [2] 4a 2c [2] 5d 27 [2] 46 69 [2] 7b }

  condition:
    any of them
}