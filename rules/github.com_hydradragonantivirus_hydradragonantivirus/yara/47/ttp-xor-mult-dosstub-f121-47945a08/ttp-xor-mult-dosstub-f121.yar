rule TTP_XOR_MULT_DOSStub_f121 {
  strings:
    $key_f121 = { a5 49 [2] d1 51 [2] 96 53 [2] d1 42 [2] 9f 4e [2] 93 44 [2] 84 4f [2] 9f 01 [2] a2 }

  condition:
    any of them
}