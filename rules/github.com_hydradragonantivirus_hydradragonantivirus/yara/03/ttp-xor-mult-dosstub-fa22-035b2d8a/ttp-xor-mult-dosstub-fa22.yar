rule TTP_XOR_MULT_DOSStub_fa22 {
  strings:
    $key_fa22 = { ae 4a [2] da 52 [2] 9d 50 [2] da 41 [2] 94 4d [2] 98 47 [2] 8f 4c [2] 94 02 [2] a9 }

  condition:
    any of them
}