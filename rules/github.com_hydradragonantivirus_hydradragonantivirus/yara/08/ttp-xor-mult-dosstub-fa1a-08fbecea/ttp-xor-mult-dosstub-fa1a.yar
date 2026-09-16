rule TTP_XOR_MULT_DOSStub_fa1a {
  strings:
    $key_fa1a = { ae 72 [2] da 6a [2] 9d 68 [2] da 79 [2] 94 75 [2] 98 7f [2] 8f 74 [2] 94 3a [2] a9 }

  condition:
    any of them
}