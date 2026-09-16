rule TTP_XOR_MULT_DOSStub_2848 {
  strings:
    $key_2848 = { 7c 20 [2] 08 38 [2] 4f 3a [2] 08 2b [2] 46 27 [2] 4a 2d [2] 5d 26 [2] 46 68 [2] 7b }

  condition:
    any of them
}