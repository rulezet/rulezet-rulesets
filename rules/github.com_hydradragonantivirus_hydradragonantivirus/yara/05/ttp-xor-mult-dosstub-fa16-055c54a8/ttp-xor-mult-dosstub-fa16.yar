rule TTP_XOR_MULT_DOSStub_fa16 {
  strings:
    $key_fa16 = { ae 7e [2] da 66 [2] 9d 64 [2] da 75 [2] 94 79 [2] 98 73 [2] 8f 78 [2] 94 36 [2] a9 }

  condition:
    any of them
}