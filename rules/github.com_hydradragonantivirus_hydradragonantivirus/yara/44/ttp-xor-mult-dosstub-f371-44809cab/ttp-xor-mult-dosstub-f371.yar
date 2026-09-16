rule TTP_XOR_MULT_DOSStub_f371 {
  strings:
    $key_f371 = { a7 19 [2] d3 01 [2] 94 03 [2] d3 12 [2] 9d 1e [2] 91 14 [2] 86 1f [2] 9d 51 [2] a0 }

  condition:
    any of them
}