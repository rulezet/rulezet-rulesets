rule TTP_XOR_MULT_DOSStub_fa48 {
  strings:
    $key_fa48 = { ae 20 [2] da 38 [2] 9d 3a [2] da 2b [2] 94 27 [2] 98 2d [2] 8f 26 [2] 94 68 [2] a9 }

  condition:
    any of them
}