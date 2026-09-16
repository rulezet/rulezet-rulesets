rule TTP_XOR_MULT_DOSStub_f3e0 {
  strings:
    $key_f3e0 = { a7 88 [2] d3 90 [2] 94 92 [2] d3 83 [2] 9d 8f [2] 91 85 [2] 86 8e [2] 9d c0 [2] a0 }

  condition:
    any of them
}