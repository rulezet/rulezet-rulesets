rule TTP_XOR_MULT_DOSStub_f600 {
  strings:
    $key_f600 = { a2 68 [2] d6 70 [2] 91 72 [2] d6 63 [2] 98 6f [2] 94 65 [2] 83 6e [2] 98 20 [2] a5 }

  condition:
    any of them
}