rule TTP_XOR_MULT_DOSStub_f53b {
  strings:
    $key_f53b = { a1 53 [2] d5 4b [2] 92 49 [2] d5 58 [2] 9b 54 [2] 97 5e [2] 80 55 [2] 9b 1b [2] a6 }

  condition:
    any of them
}