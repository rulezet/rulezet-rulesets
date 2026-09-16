rule TTP_XOR_MULT_DOSStub_f23b {
  strings:
    $key_f23b = { a6 53 [2] d2 4b [2] 95 49 [2] d2 58 [2] 9c 54 [2] 90 5e [2] 87 55 [2] 9c 1b [2] a1 }

  condition:
    any of them
}