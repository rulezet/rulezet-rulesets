rule TTP_XOR_MULT_DOSStub_f351 {
  strings:
    $key_f351 = { a7 39 [2] d3 21 [2] 94 23 [2] d3 32 [2] 9d 3e [2] 91 34 [2] 86 3f [2] 9d 71 [2] a0 }

  condition:
    any of them
}