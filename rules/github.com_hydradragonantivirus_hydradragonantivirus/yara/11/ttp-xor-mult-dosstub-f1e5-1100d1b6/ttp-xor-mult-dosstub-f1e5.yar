rule TTP_XOR_MULT_DOSStub_f1e5 {
  strings:
    $key_f1e5 = { a5 8d [2] d1 95 [2] 96 97 [2] d1 86 [2] 9f 8a [2] 93 80 [2] 84 8b [2] 9f c5 [2] a2 }

  condition:
    any of them
}