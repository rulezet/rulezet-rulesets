rule TTP_XOR_MULT_DOSStub_545d {
  strings:
    $key_545d = { 00 35 [2] 74 2d [2] 33 2f [2] 74 3e [2] 3a 32 [2] 36 38 [2] 21 33 [2] 3a 7d [2] 07 }

  condition:
    any of them
}