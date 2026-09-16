rule TTP_XOR_MULT_DOSStub_3a10 {
  strings:
    $key_3a10 = { 6e 78 [2] 1a 60 [2] 5d 62 [2] 1a 73 [2] 54 7f [2] 58 75 [2] 4f 7e [2] 54 30 [2] 69 }

  condition:
    any of them
}