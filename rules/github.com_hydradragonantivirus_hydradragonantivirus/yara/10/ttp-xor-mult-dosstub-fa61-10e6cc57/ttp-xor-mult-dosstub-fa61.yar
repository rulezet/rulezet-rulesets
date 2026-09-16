rule TTP_XOR_MULT_DOSStub_fa61 {
  strings:
    $key_fa61 = { ae 09 [2] da 11 [2] 9d 13 [2] da 02 [2] 94 0e [2] 98 04 [2] 8f 0f [2] 94 41 [2] a9 }

  condition:
    any of them
}