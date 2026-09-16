rule TTP_XOR_MULT_DOSStub_f330 {
  strings:
    $key_f330 = { a7 58 [2] d3 40 [2] 94 42 [2] d3 53 [2] 9d 5f [2] 91 55 [2] 86 5e [2] 9d 10 [2] a0 }

  condition:
    any of them
}