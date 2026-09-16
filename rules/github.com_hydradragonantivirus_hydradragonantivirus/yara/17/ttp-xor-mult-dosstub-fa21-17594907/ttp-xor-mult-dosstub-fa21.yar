rule TTP_XOR_MULT_DOSStub_fa21 {
  strings:
    $key_fa21 = { ae 49 [2] da 51 [2] 9d 53 [2] da 42 [2] 94 4e [2] 98 44 [2] 8f 4f [2] 94 01 [2] a9 }

  condition:
    any of them
}