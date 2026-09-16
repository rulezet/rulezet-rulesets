rule TTP_XOR_MULT_DOSStub_fa3d {
  strings:
    $key_fa3d = { ae 55 [2] da 4d [2] 9d 4f [2] da 5e [2] 94 52 [2] 98 58 [2] 8f 53 [2] 94 1d [2] a9 }

  condition:
    any of them
}