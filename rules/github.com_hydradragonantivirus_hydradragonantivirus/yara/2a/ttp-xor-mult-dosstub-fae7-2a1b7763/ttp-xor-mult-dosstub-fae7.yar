rule TTP_XOR_MULT_DOSStub_fae7 {
  strings:
    $key_fae7 = { ae 8f [2] da 97 [2] 9d 95 [2] da 84 [2] 94 88 [2] 98 82 [2] 8f 89 [2] 94 c7 [2] a9 }

  condition:
    any of them
}