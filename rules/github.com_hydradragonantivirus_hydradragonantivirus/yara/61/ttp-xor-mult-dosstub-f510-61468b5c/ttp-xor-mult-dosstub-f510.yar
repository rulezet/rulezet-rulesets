rule TTP_XOR_MULT_DOSStub_f510 {
  strings:
    $key_f510 = { a1 78 [2] d5 60 [2] 92 62 [2] d5 73 [2] 9b 7f [2] 97 75 [2] 80 7e [2] 9b 30 [2] a6 }

  condition:
    any of them
}