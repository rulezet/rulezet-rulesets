rule TTP_XOR_MULT_DOSStub_2812 {
  strings:
    $key_2812 = { 7c 7a [2] 08 62 [2] 4f 60 [2] 08 71 [2] 46 7d [2] 4a 77 [2] 5d 7c [2] 46 32 [2] 7b }

  condition:
    any of them
}