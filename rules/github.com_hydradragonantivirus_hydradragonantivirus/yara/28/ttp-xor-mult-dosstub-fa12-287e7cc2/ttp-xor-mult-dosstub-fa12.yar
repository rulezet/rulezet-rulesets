rule TTP_XOR_MULT_DOSStub_fa12 {
  strings:
    $key_fa12 = { ae 7a [2] da 62 [2] 9d 60 [2] da 71 [2] 94 7d [2] 98 77 [2] 8f 7c [2] 94 32 [2] a9 }

  condition:
    any of them
}