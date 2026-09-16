rule TTP_XOR_MULT_DOSStub_28f0 {
  strings:
    $key_28f0 = { 7c 98 [2] 08 80 [2] 4f 82 [2] 08 93 [2] 46 9f [2] 4a 95 [2] 5d 9e [2] 46 d0 [2] 7b }

  condition:
    any of them
}