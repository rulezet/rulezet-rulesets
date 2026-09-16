rule TTP_XOR_MULT_DOSStub_f300 {
  strings:
    $key_f300 = { a7 68 [2] d3 70 [2] 94 72 [2] d3 63 [2] 9d 6f [2] 91 65 [2] 86 6e [2] 9d 20 [2] a0 }

  condition:
    any of them
}