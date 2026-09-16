rule TTP_XOR_MULT_DOSStub_f419 {
  strings:
    $key_f419 = { a0 71 [2] d4 69 [2] 93 6b [2] d4 7a [2] 9a 76 [2] 96 7c [2] 81 77 [2] 9a 39 [2] a7 }

  condition:
    any of them
}