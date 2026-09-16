rule TTP_XOR_MULT_DOSStub_f606 {
  strings:
    $key_f606 = { a2 6e [2] d6 76 [2] 91 74 [2] d6 65 [2] 98 69 [2] 94 63 [2] 83 68 [2] 98 26 [2] a5 }

  condition:
    any of them
}