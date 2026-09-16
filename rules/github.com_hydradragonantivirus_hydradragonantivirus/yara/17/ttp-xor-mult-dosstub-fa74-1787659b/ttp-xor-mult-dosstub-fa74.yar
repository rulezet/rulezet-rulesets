rule TTP_XOR_MULT_DOSStub_fa74 {
  strings:
    $key_fa74 = { ae 1c [2] da 04 [2] 9d 06 [2] da 17 [2] 94 1b [2] 98 11 [2] 8f 1a [2] 94 54 [2] a9 }

  condition:
    any of them
}