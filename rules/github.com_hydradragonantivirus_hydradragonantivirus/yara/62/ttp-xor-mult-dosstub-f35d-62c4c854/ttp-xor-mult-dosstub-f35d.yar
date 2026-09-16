rule TTP_XOR_MULT_DOSStub_f35d {
  strings:
    $key_f35d = { a7 35 [2] d3 2d [2] 94 2f [2] d3 3e [2] 9d 32 [2] 91 38 [2] 86 33 [2] 9d 7d [2] a0 }

  condition:
    any of them
}