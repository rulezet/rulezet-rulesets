rule TTP_XOR_MULT_DOSStub_fa64 {
  strings:
    $key_fa64 = { ae 0c [2] da 14 [2] 9d 16 [2] da 07 [2] 94 0b [2] 98 01 [2] 8f 0a [2] 94 44 [2] a9 }

  condition:
    any of them
}