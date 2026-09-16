rule TTP_XOR_MULT_DOSStub_f621 {
  strings:
    $key_f621 = { a2 49 [2] d6 51 [2] 91 53 [2] d6 42 [2] 98 4e [2] 94 44 [2] 83 4f [2] 98 01 [2] a5 }

  condition:
    any of them
}