rule TTP_XOR_MULT_DOSStub_fa24 {
  strings:
    $key_fa24 = { ae 4c [2] da 54 [2] 9d 56 [2] da 47 [2] 94 4b [2] 98 41 [2] 8f 4a [2] 94 04 [2] a9 }

  condition:
    any of them
}