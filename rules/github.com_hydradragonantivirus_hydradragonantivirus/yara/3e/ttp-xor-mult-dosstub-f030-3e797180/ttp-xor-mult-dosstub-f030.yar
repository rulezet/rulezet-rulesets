rule TTP_XOR_MULT_DOSStub_f030 {
  strings:
    $key_f030 = { a4 58 [2] d0 40 [2] 97 42 [2] d0 53 [2] 9e 5f [2] 92 55 [2] 85 5e [2] 9e 10 [2] a3 }

  condition:
    any of them
}