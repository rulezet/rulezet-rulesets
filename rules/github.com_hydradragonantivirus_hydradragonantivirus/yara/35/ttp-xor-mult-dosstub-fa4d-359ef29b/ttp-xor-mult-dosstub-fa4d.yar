rule TTP_XOR_MULT_DOSStub_fa4d {
  strings:
    $key_fa4d = { ae 25 [2] da 3d [2] 9d 3f [2] da 2e [2] 94 22 [2] 98 28 [2] 8f 23 [2] 94 6d [2] a9 }

  condition:
    any of them
}