rule TTP_XOR_MULT_DOSStub_fa76 {
  strings:
    $key_fa76 = { ae 1e [2] da 06 [2] 9d 04 [2] da 15 [2] 94 19 [2] 98 13 [2] 8f 18 [2] 94 56 [2] a9 }

  condition:
    any of them
}