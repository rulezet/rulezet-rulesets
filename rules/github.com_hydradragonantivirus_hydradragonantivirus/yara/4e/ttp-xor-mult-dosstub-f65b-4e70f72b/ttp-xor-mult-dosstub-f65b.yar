rule TTP_XOR_MULT_DOSStub_f65b {
  strings:
    $key_f65b = { a2 33 [2] d6 2b [2] 91 29 [2] d6 38 [2] 98 34 [2] 94 3e [2] 83 35 [2] 98 7b [2] a5 }

  condition:
    any of them
}