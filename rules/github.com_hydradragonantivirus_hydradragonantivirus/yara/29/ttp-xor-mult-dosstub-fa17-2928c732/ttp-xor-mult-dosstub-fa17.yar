rule TTP_XOR_MULT_DOSStub_fa17 {
  strings:
    $key_fa17 = { ae 7f [2] da 67 [2] 9d 65 [2] da 74 [2] 94 78 [2] 98 72 [2] 8f 79 [2] 94 37 [2] a9 }

  condition:
    any of them
}