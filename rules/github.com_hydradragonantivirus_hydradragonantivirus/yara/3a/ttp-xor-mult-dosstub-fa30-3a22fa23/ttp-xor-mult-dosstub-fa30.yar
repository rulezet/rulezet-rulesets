rule TTP_XOR_MULT_DOSStub_fa30 {
  strings:
    $key_fa30 = { ae 58 [2] da 40 [2] 9d 42 [2] da 53 [2] 94 5f [2] 98 55 [2] 8f 5e [2] 94 10 [2] a9 }

  condition:
    any of them
}