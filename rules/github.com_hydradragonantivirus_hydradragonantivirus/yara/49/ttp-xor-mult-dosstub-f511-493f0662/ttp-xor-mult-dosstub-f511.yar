rule TTP_XOR_MULT_DOSStub_f511 {
  strings:
    $key_f511 = { a1 79 [2] d5 61 [2] 92 63 [2] d5 72 [2] 9b 7e [2] 97 74 [2] 80 7f [2] 9b 31 [2] a6 }

  condition:
    any of them
}