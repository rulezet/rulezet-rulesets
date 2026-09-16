rule TTP_XOR_MULT_DOSStub_faf1 {
  strings:
    $key_faf1 = { ae 99 [2] da 81 [2] 9d 83 [2] da 92 [2] 94 9e [2] 98 94 [2] 8f 9f [2] 94 d1 [2] a9 }

  condition:
    any of them
}