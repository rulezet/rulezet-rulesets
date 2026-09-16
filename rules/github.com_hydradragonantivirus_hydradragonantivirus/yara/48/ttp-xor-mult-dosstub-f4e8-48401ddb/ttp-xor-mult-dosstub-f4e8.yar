rule TTP_XOR_MULT_DOSStub_f4e8 {
  strings:
    $key_f4e8 = { a0 80 [2] d4 98 [2] 93 9a [2] d4 8b [2] 9a 87 [2] 96 8d [2] 81 86 [2] 9a c8 [2] a7 }

  condition:
    any of them
}