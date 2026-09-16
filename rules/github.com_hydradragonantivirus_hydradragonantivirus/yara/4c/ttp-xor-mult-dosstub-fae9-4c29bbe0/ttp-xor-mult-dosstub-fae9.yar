rule TTP_XOR_MULT_DOSStub_fae9 {
  strings:
    $key_fae9 = { ae 81 [2] da 99 [2] 9d 9b [2] da 8a [2] 94 86 [2] 98 8c [2] 8f 87 [2] 94 c9 [2] a9 }

  condition:
    any of them
}