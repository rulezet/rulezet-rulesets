rule TTP_XOR_MULT_DOSStub_f31b {
  strings:
    $key_f31b = { a7 73 [2] d3 6b [2] 94 69 [2] d3 78 [2] 9d 74 [2] 91 7e [2] 86 75 [2] 9d 3b [2] a0 }

  condition:
    any of them
}