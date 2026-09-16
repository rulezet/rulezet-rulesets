rule TTP_XOR_MULT_DOSStub_f1f9 {
  strings:
    $key_f1f9 = { a5 91 [2] d1 89 [2] 96 8b [2] d1 9a [2] 9f 96 [2] 93 9c [2] 84 97 [2] 9f d9 [2] a2 }

  condition:
    any of them
}