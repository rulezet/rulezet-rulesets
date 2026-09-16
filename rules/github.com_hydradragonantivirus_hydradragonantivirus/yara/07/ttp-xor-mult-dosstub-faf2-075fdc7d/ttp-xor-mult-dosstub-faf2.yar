rule TTP_XOR_MULT_DOSStub_faf2 {
  strings:
    $key_faf2 = { ae 9a [2] da 82 [2] 9d 80 [2] da 91 [2] 94 9d [2] 98 97 [2] 8f 9c [2] 94 d2 [2] a9 }

  condition:
    any of them
}