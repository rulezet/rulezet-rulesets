rule TTP_XOR_MULT_DOSStub_f30b {
  strings:
    $key_f30b = { a7 63 [2] d3 7b [2] 94 79 [2] d3 68 [2] 9d 64 [2] 91 6e [2] 86 65 [2] 9d 2b [2] a0 }

  condition:
    any of them
}