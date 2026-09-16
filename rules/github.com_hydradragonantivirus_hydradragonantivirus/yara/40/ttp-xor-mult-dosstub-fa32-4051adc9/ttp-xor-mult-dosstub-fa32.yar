rule TTP_XOR_MULT_DOSStub_fa32 {
  strings:
    $key_fa32 = { ae 5a [2] da 42 [2] 9d 40 [2] da 51 [2] 94 5d [2] 98 57 [2] 8f 5c [2] 94 12 [2] a9 }

  condition:
    any of them
}