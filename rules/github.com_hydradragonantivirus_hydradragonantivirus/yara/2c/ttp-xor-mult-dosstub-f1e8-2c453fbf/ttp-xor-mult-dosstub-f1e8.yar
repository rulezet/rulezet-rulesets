rule TTP_XOR_MULT_DOSStub_f1e8 {
  strings:
    $key_f1e8 = { a5 80 [2] d1 98 [2] 96 9a [2] d1 8b [2] 9f 87 [2] 93 8d [2] 84 86 [2] 9f c8 [2] a2 }

  condition:
    any of them
}