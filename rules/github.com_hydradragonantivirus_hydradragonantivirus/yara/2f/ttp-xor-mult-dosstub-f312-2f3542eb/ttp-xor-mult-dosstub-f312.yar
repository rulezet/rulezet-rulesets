rule TTP_XOR_MULT_DOSStub_f312 {
  strings:
    $key_f312 = { a7 7a [2] d3 62 [2] 94 60 [2] d3 71 [2] 9d 7d [2] 91 77 [2] 86 7c [2] 9d 32 [2] a0 }

  condition:
    any of them
}