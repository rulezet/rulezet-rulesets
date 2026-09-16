rule TTP_XOR_MULT_DOSStub_fa59 {
  strings:
    $key_fa59 = { ae 31 [2] da 29 [2] 9d 2b [2] da 3a [2] 94 36 [2] 98 3c [2] 8f 37 [2] 94 79 [2] a9 }

  condition:
    any of them
}