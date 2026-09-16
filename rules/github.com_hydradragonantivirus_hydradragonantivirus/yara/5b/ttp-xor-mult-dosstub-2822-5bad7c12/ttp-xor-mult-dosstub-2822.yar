rule TTP_XOR_MULT_DOSStub_2822 {
  strings:
    $key_2822 = { 7c 4a [2] 08 52 [2] 4f 50 [2] 08 41 [2] 46 4d [2] 4a 47 [2] 5d 4c [2] 46 02 [2] 7b }

  condition:
    any of them
}