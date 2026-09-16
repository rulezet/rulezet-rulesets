rule TTP_XOR_MULT_DOSStub_f366 {
  strings:
    $key_f366 = { a7 0e [2] d3 16 [2] 94 14 [2] d3 05 [2] 9d 09 [2] 91 03 [2] 86 08 [2] 9d 46 [2] a0 }

  condition:
    any of them
}