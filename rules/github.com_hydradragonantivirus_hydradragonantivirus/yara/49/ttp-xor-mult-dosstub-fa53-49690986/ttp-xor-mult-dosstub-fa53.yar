rule TTP_XOR_MULT_DOSStub_fa53 {
  strings:
    $key_fa53 = { ae 3b [2] da 23 [2] 9d 21 [2] da 30 [2] 94 3c [2] 98 36 [2] 8f 3d [2] 94 73 [2] a9 }

  condition:
    any of them
}