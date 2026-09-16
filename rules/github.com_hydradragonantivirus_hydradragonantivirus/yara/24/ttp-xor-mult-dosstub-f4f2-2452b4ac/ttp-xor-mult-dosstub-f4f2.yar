rule TTP_XOR_MULT_DOSStub_f4f2 {
  strings:
    $key_f4f2 = { a0 9a [2] d4 82 [2] 93 80 [2] d4 91 [2] 9a 9d [2] 96 97 [2] 81 9c [2] 9a d2 [2] a7 }

  condition:
    any of them
}