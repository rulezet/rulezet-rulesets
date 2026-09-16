rule TTP_XOR_MULT_DOSStub_fa5d {
  strings:
    $key_fa5d = { ae 35 [2] da 2d [2] 9d 2f [2] da 3e [2] 94 32 [2] 98 38 [2] 8f 33 [2] 94 7d [2] a9 }

  condition:
    any of them
}