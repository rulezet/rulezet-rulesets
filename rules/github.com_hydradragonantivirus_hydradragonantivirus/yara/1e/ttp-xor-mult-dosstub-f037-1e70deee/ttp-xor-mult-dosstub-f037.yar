rule TTP_XOR_MULT_DOSStub_f037 {
  strings:
    $key_f037 = { a4 5f [2] d0 47 [2] 97 45 [2] d0 54 [2] 9e 58 [2] 92 52 [2] 85 59 [2] 9e 17 [2] a3 }

  condition:
    any of them
}