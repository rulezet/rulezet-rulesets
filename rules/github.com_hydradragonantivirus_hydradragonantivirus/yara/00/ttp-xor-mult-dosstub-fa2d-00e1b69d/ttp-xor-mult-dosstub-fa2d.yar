rule TTP_XOR_MULT_DOSStub_fa2d {
  strings:
    $key_fa2d = { ae 45 [2] da 5d [2] 9d 5f [2] da 4e [2] 94 42 [2] 98 48 [2] 8f 43 [2] 94 0d [2] a9 }

  condition:
    any of them
}