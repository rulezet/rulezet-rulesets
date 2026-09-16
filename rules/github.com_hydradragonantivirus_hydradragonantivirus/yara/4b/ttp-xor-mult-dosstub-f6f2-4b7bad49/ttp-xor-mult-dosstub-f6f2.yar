rule TTP_XOR_MULT_DOSStub_f6f2 {
  strings:
    $key_f6f2 = { a2 9a [2] d6 82 [2] 91 80 [2] d6 91 [2] 98 9d [2] 94 97 [2] 83 9c [2] 98 d2 [2] a5 }

  condition:
    any of them
}