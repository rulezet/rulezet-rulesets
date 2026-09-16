rule TTP_XOR_MULT_DOSStub_fa7a {
  strings:
    $key_fa7a = { ae 12 [2] da 0a [2] 9d 08 [2] da 19 [2] 94 15 [2] 98 1f [2] 8f 14 [2] 94 5a [2] a9 }

  condition:
    any of them
}