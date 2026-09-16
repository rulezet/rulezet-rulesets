rule TTP_XOR_MULT_DOSStub_f03b {
  strings:
    $key_f03b = { a4 53 [2] d0 4b [2] 97 49 [2] d0 58 [2] 9e 54 [2] 92 5e [2] 85 55 [2] 9e 1b [2] a3 }

  condition:
    any of them
}