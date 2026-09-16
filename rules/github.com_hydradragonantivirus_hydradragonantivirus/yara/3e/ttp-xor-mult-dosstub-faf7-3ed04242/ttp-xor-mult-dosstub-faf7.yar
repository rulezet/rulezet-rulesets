rule TTP_XOR_MULT_DOSStub_faf7 {
  strings:
    $key_faf7 = { ae 9f [2] da 87 [2] 9d 85 [2] da 94 [2] 94 98 [2] 98 92 [2] 8f 99 [2] 94 d7 [2] a9 }

  condition:
    any of them
}