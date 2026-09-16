rule TTP_XOR_MULT_DOSStub_f320 {
  strings:
    $key_f320 = { a7 48 [2] d3 50 [2] 94 52 [2] d3 43 [2] 9d 4f [2] 91 45 [2] 86 4e [2] 9d 00 [2] a0 }

  condition:
    any of them
}