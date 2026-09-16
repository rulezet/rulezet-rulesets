rule TTP_XOR_MULT_DOSStub_f311 {
  strings:
    $key_f311 = { a7 79 [2] d3 61 [2] 94 63 [2] d3 72 [2] 9d 7e [2] 91 74 [2] 86 7f [2] 9d 31 [2] a0 }

  condition:
    any of them
}