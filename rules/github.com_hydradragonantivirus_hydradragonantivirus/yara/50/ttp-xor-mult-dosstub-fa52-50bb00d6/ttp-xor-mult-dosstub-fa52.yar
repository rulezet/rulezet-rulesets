rule TTP_XOR_MULT_DOSStub_fa52 {
  strings:
    $key_fa52 = { ae 3a [2] da 22 [2] 9d 20 [2] da 31 [2] 94 3d [2] 98 37 [2] 8f 3c [2] 94 72 [2] a9 }

  condition:
    any of them
}