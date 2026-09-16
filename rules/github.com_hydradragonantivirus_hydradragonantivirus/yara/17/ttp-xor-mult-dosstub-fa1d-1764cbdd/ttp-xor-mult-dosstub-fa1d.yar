rule TTP_XOR_MULT_DOSStub_fa1d {
  strings:
    $key_fa1d = { ae 75 [2] da 6d [2] 9d 6f [2] da 7e [2] 94 72 [2] 98 78 [2] 8f 73 [2] 94 3d [2] a9 }

  condition:
    any of them
}