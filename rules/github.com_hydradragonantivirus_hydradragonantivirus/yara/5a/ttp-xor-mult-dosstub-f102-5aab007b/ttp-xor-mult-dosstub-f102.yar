rule TTP_XOR_MULT_DOSStub_f102 {
  strings:
    $key_f102 = { a5 6a [2] d1 72 [2] 96 70 [2] d1 61 [2] 9f 6d [2] 93 67 [2] 84 6c [2] 9f 22 [2] a2 }

  condition:
    any of them
}