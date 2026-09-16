rule TTP_XOR_MULT_DOSStub_fa78 {
  strings:
    $key_fa78 = { ae 10 [2] da 08 [2] 9d 0a [2] da 1b [2] 94 17 [2] 98 1d [2] 8f 16 [2] 94 58 [2] a9 }

  condition:
    any of them
}