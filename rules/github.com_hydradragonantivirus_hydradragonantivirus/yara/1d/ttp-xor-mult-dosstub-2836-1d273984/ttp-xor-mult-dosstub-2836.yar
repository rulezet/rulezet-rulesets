rule TTP_XOR_MULT_DOSStub_2836 {
  strings:
    $key_2836 = { 7c 5e [2] 08 46 [2] 4f 44 [2] 08 55 [2] 46 59 [2] 4a 53 [2] 5d 58 [2] 46 16 [2] 7b }

  condition:
    any of them
}