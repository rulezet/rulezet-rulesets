rule TTP_XOR_MULT_DOSStub_faf6 {
  strings:
    $key_faf6 = { ae 9e [2] da 86 [2] 9d 84 [2] da 95 [2] 94 99 [2] 98 93 [2] 8f 98 [2] 94 d6 [2] a9 }

  condition:
    any of them
}