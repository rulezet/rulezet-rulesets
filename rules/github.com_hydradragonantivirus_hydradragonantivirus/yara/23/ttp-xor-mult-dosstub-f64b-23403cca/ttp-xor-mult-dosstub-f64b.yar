rule TTP_XOR_MULT_DOSStub_f64b {
  strings:
    $key_f64b = { a2 23 [2] d6 3b [2] 91 39 [2] d6 28 [2] 98 24 [2] 94 2e [2] 83 25 [2] 98 6b [2] a5 }

  condition:
    any of them
}