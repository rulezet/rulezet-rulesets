rule TTP_XOR_MULT_DOSStub_fa6d {
  strings:
    $key_fa6d = { ae 05 [2] da 1d [2] 9d 1f [2] da 0e [2] 94 02 [2] 98 08 [2] 8f 03 [2] 94 4d [2] a9 }

  condition:
    any of them
}