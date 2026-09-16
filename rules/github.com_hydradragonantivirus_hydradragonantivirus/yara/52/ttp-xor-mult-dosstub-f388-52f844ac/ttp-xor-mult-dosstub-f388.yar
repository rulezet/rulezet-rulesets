rule TTP_XOR_MULT_DOSStub_f388 {
  strings:
    $key_f388 = { a7 e0 [2] d3 f8 [2] 94 fa [2] d3 eb [2] 9d e7 [2] 91 ed [2] 86 e6 [2] 9d a8 [2] a0 }

  condition:
    any of them
}