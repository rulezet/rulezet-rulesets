rule TTP_XOR_MULT_DOSStub_fa7f {
  strings:
    $key_fa7f = { ae 17 [2] da 0f [2] 9d 0d [2] da 1c [2] 94 10 [2] 98 1a [2] 8f 11 [2] 94 5f [2] a9 }

  condition:
    any of them
}