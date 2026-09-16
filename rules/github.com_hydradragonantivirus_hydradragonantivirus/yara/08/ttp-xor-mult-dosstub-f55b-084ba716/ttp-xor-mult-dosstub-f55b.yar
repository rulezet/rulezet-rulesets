rule TTP_XOR_MULT_DOSStub_f55b {
  strings:
    $key_f55b = { a1 33 [2] d5 2b [2] 92 29 [2] d5 38 [2] 9b 34 [2] 97 3e [2] 80 35 [2] 9b 7b [2] a6 }

  condition:
    any of them
}