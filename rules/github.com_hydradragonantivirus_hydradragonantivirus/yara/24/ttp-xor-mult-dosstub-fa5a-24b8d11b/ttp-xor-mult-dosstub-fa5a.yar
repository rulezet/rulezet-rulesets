rule TTP_XOR_MULT_DOSStub_fa5a {
  strings:
    $key_fa5a = { ae 32 [2] da 2a [2] 9d 28 [2] da 39 [2] 94 35 [2] 98 3f [2] 8f 34 [2] 94 7a [2] a9 }

  condition:
    any of them
}