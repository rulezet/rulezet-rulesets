rule TTP_XOR_MULT_DOSStub_fa33 {
  strings:
    $key_fa33 = { ae 5b [2] da 43 [2] 9d 41 [2] da 50 [2] 94 5c [2] 98 56 [2] 8f 5d [2] 94 13 [2] a9 }

  condition:
    any of them
}