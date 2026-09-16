rule TTP_XOR_MULT_DOSStub_2816 {
  strings:
    $key_2816 = { 7c 7e [2] 08 66 [2] 4f 64 [2] 08 75 [2] 46 79 [2] 4a 73 [2] 5d 78 [2] 46 36 [2] 7b }

  condition:
    any of them
}