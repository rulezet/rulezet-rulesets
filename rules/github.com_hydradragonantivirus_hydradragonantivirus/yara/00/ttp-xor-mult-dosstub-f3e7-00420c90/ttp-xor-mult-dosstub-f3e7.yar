rule TTP_XOR_MULT_DOSStub_f3e7 {
  strings:
    $key_f3e7 = { a7 8f [2] d3 97 [2] 94 95 [2] d3 84 [2] 9d 88 [2] 91 82 [2] 86 89 [2] 9d c7 [2] a0 }

  condition:
    any of them
}