rule TTP_XOR_MULT_DOSStub_faf9 {
  strings:
    $key_faf9 = { ae 91 [2] da 89 [2] 9d 8b [2] da 9a [2] 94 96 [2] 98 9c [2] 8f 97 [2] 94 d9 [2] a9 }

  condition:
    any of them
}