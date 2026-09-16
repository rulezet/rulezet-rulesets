rule TTP_XOR_MULT_DOSStub_fa26 {
  strings:
    $key_fa26 = { ae 4e [2] da 56 [2] 9d 54 [2] da 45 [2] 94 49 [2] 98 43 [2] 8f 48 [2] 94 06 [2] a9 }

  condition:
    any of them
}