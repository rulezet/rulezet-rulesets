rule TTP_XOR_MULT_DOSStub_f409 {
  strings:
    $key_f409 = { a0 61 [2] d4 79 [2] 93 7b [2] d4 6a [2] 9a 66 [2] 96 6c [2] 81 67 [2] 9a 29 [2] a7 }

  condition:
    any of them
}