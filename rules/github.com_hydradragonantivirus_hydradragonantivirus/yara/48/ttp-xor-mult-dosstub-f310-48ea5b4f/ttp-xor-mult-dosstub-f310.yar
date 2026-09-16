rule TTP_XOR_MULT_DOSStub_f310 {
  strings:
    $key_f310 = { a7 78 [2] d3 60 [2] 94 62 [2] d3 73 [2] 9d 7f [2] 91 75 [2] 86 7e [2] 9d 30 [2] a0 }

  condition:
    any of them
}