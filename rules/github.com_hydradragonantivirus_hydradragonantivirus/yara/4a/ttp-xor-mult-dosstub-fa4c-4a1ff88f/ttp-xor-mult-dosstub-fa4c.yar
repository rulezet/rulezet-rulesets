rule TTP_XOR_MULT_DOSStub_fa4c {
  strings:
    $key_fa4c = { ae 24 [2] da 3c [2] 9d 3e [2] da 2f [2] 94 23 [2] 98 29 [2] 8f 22 [2] 94 6c [2] a9 }

  condition:
    any of them
}