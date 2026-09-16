rule TTP_XOR_MULT_DOSStub_fa46 {
  strings:
    $key_fa46 = { ae 2e [2] da 36 [2] 9d 34 [2] da 25 [2] 94 29 [2] 98 23 [2] 8f 28 [2] 94 66 [2] a9 }

  condition:
    any of them
}