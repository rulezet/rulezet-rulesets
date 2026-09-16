rule TTP_XOR_MULT_DOSStub_fa14 {
  strings:
    $key_fa14 = { ae 7c [2] da 64 [2] 9d 66 [2] da 77 [2] 94 7b [2] 98 71 [2] 8f 7a [2] 94 34 [2] a9 }

  condition:
    any of them
}