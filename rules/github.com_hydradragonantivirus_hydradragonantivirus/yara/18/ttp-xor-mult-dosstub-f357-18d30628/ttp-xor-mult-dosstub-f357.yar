rule TTP_XOR_MULT_DOSStub_f357 {
  strings:
    $key_f357 = { a7 3f [2] d3 27 [2] 94 25 [2] d3 34 [2] 9d 38 [2] 91 32 [2] 86 39 [2] 9d 77 [2] a0 }

  condition:
    any of them
}