rule TTP_XOR_MULT_DOSStub_f1f2 {
  strings:
    $key_f1f2 = { a5 9a [2] d1 82 [2] 96 80 [2] d1 91 [2] 9f 9d [2] 93 97 [2] 84 9c [2] 9f d2 [2] a2 }

  condition:
    any of them
}