rule TTP_XOR_MULT_DOSStub_f561 {
  strings:
    $key_f561 = { a1 09 [2] d5 11 [2] 92 13 [2] d5 02 [2] 9b 0e [2] 97 04 [2] 80 0f [2] 9b 41 [2] a6 }

  condition:
    any of them
}