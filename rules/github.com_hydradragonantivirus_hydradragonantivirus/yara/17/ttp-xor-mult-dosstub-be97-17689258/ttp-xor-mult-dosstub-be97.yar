rule TTP_XOR_MULT_DOSStub_be97 {
  strings:
    $key_be97 = { ea ff [2] 9e e7 [2] d9 e5 [2] 9e f4 [2] d0 f8 [2] dc f2 [2] cb f9 [2] d0 b7 [2] ed }

  condition:
    any of them
}