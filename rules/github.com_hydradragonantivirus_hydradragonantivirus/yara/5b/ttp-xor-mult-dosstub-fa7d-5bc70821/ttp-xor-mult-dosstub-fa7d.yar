rule TTP_XOR_MULT_DOSStub_fa7d {
  strings:
    $key_fa7d = { ae 15 [2] da 0d [2] 9d 0f [2] da 1e [2] 94 12 [2] 98 18 [2] 8f 13 [2] 94 5d [2] a9 }

  condition:
    any of them
}