rule TTP_XOR_MULT_DOSStub_fa4f {
  strings:
    $key_fa4f = { ae 27 [2] da 3f [2] 9d 3d [2] da 2c [2] 94 20 [2] 98 2a [2] 8f 21 [2] 94 6f [2] a9 }

  condition:
    any of them
}