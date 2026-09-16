rule TTP_XOR_MULT_DOSStub_faf4 {
  strings:
    $key_faf4 = { ae 9c [2] da 84 [2] 9d 86 [2] da 97 [2] 94 9b [2] 98 91 [2] 8f 9a [2] 94 d4 [2] a9 }

  condition:
    any of them
}