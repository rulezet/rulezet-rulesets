rule TTP_XOR_MULT_DOSStub_fa55 {
  strings:
    $key_fa55 = { ae 3d [2] da 25 [2] 9d 27 [2] da 36 [2] 94 3a [2] 98 30 [2] 8f 3b [2] 94 75 [2] a9 }

  condition:
    any of them
}