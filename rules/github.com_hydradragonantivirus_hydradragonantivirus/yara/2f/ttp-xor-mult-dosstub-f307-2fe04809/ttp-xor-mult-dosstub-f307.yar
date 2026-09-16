rule TTP_XOR_MULT_DOSStub_f307 {
  strings:
    $key_f307 = { a7 6f [2] d3 77 [2] 94 75 [2] d3 64 [2] 9d 68 [2] 91 62 [2] 86 69 [2] 9d 27 [2] a0 }

  condition:
    any of them
}