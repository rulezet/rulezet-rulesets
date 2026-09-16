rule TTP_XOR_MULT_DOSStub_f385 {
  strings:
    $key_f385 = { a7 ed [2] d3 f5 [2] 94 f7 [2] d3 e6 [2] 9d ea [2] 91 e0 [2] 86 eb [2] 9d a5 [2] a0 }

  condition:
    any of them
}