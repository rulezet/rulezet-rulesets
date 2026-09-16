rule TTP_XOR_MULT_DOSStub_f036 {
  strings:
    $key_f036 = { a4 5e [2] d0 46 [2] 97 44 [2] d0 55 [2] 9e 59 [2] 92 53 [2] 85 58 [2] 9e 16 [2] a3 }

  condition:
    any of them
}