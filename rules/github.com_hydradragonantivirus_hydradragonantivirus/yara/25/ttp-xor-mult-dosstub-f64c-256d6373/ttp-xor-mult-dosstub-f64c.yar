rule TTP_XOR_MULT_DOSStub_f64c {
  strings:
    $key_f64c = { a2 24 [2] d6 3c [2] 91 3e [2] d6 2f [2] 98 23 [2] 94 29 [2] 83 22 [2] 98 6c [2] a5 }

  condition:
    any of them
}