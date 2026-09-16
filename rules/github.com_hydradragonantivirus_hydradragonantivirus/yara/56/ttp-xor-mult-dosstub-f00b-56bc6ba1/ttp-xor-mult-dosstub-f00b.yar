rule TTP_XOR_MULT_DOSStub_f00b {
  strings:
    $key_f00b = { a4 63 [2] d0 7b [2] 97 79 [2] d0 68 [2] 9e 64 [2] 92 6e [2] 85 65 [2] 9e 2b [2] a3 }

  condition:
    any of them
}