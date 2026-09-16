rule TTP_XOR_MULT_DOSStub_f114 {
  strings:
    $key_f114 = { a5 7c [2] d1 64 [2] 96 66 [2] d1 77 [2] 9f 7b [2] 93 71 [2] 84 7a [2] 9f 34 [2] a2 }

  condition:
    any of them
}