rule TTP_XOR_MULT_DOSStub_2850 {
  strings:
    $key_2850 = { 7c 38 [2] 08 20 [2] 4f 22 [2] 08 33 [2] 46 3f [2] 4a 35 [2] 5d 3e [2] 46 70 [2] 7b }

  condition:
    any of them
}