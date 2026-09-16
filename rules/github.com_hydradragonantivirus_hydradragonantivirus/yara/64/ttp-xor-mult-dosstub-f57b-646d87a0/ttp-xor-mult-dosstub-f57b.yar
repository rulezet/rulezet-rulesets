rule TTP_XOR_MULT_DOSStub_f57b {
  strings:
    $key_f57b = { a1 13 [2] d5 0b [2] 92 09 [2] d5 18 [2] 9b 14 [2] 97 1e [2] 80 15 [2] 9b 5b [2] a6 }

  condition:
    any of them
}