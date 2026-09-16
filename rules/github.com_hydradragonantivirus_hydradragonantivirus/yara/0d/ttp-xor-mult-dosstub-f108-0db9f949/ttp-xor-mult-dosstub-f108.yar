rule TTP_XOR_MULT_DOSStub_f108 {
  strings:
    $key_f108 = { a5 60 [2] d1 78 [2] 96 7a [2] d1 6b [2] 9f 67 [2] 93 6d [2] 84 66 [2] 9f 28 [2] a2 }

  condition:
    any of them
}