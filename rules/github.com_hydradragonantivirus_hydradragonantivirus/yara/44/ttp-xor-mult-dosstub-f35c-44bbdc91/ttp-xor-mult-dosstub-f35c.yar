rule TTP_XOR_MULT_DOSStub_f35c {
  strings:
    $key_f35c = { a7 34 [2] d3 2c [2] 94 2e [2] d3 3f [2] 9d 33 [2] 91 39 [2] 86 32 [2] 9d 7c [2] a0 }

  condition:
    any of them
}