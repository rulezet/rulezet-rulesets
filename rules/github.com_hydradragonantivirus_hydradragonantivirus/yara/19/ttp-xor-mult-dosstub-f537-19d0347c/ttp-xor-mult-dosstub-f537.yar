rule TTP_XOR_MULT_DOSStub_f537 {
  strings:
    $key_f537 = { a1 5f [2] d5 47 [2] 92 45 [2] d5 54 [2] 9b 58 [2] 97 52 [2] 80 59 [2] 9b 17 [2] a6 }

  condition:
    any of them
}