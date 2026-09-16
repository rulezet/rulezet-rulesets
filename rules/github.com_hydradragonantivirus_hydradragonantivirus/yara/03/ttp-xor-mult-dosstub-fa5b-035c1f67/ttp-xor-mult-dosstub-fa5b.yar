rule TTP_XOR_MULT_DOSStub_fa5b {
  strings:
    $key_fa5b = { ae 33 [2] da 2b [2] 9d 29 [2] da 38 [2] 94 34 [2] 98 3e [2] 8f 35 [2] 94 7b [2] a9 }

  condition:
    any of them
}