rule TTP_XOR_MULT_DOSStub_fa36 {
  strings:
    $key_fa36 = { ae 5e [2] da 46 [2] 9d 44 [2] da 55 [2] 94 59 [2] 98 53 [2] 8f 58 [2] 94 16 [2] a9 }

  condition:
    any of them
}