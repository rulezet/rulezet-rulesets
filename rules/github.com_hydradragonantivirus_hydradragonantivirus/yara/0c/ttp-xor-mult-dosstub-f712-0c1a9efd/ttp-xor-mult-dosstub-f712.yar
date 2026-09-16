rule TTP_XOR_MULT_DOSStub_f712 {
  strings:
    $key_f712 = { a3 7a [2] d7 62 [2] 90 60 [2] d7 71 [2] 99 7d [2] 95 77 [2] 82 7c [2] 99 32 [2] a4 }

  condition:
    any of them
}