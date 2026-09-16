rule TTP_XOR_MULT_DOSStub_f321 {
  strings:
    $key_f321 = { a7 49 [2] d3 51 [2] 94 53 [2] d3 42 [2] 9d 4e [2] 91 44 [2] 86 4f [2] 9d 01 [2] a0 }

  condition:
    any of them
}