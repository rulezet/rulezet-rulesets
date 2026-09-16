rule TTP_XOR_MULT_DOSStub_fa05 {
  strings:
    $key_fa05 = { ae 6d [2] da 75 [2] 9d 77 [2] da 66 [2] 94 6a [2] 98 60 [2] 8f 6b [2] 94 25 [2] a9 }

  condition:
    any of them
}