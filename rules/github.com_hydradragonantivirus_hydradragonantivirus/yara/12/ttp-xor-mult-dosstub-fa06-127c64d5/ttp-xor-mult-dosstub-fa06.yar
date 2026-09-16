rule TTP_XOR_MULT_DOSStub_fa06 {
  strings:
    $key_fa06 = { ae 6e [2] da 76 [2] 9d 74 [2] da 65 [2] 94 69 [2] 98 63 [2] 8f 68 [2] 94 26 [2] a9 }

  condition:
    any of them
}