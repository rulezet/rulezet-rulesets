rule TTP_XOR_MULT_DOSStub_f33d {
  strings:
    $key_f33d = { a7 55 [2] d3 4d [2] 94 4f [2] d3 5e [2] 9d 52 [2] 91 58 [2] 86 53 [2] 9d 1d [2] a0 }

  condition:
    any of them
}