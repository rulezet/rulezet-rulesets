rule TTP_XOR_MULT_DOSStub_fa27 {
  strings:
    $key_fa27 = { ae 4f [2] da 57 [2] 9d 55 [2] da 44 [2] 94 48 [2] 98 42 [2] 8f 49 [2] 94 07 [2] a9 }

  condition:
    any of them
}