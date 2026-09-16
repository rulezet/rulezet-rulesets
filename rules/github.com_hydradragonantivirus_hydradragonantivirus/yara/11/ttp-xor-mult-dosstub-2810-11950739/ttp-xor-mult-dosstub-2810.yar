rule TTP_XOR_MULT_DOSStub_2810 {
  strings:
    $key_2810 = { 7c 78 [2] 08 60 [2] 4f 62 [2] 08 73 [2] 46 7f [2] 4a 75 [2] 5d 7e [2] 46 30 [2] 7b }

  condition:
    any of them
}