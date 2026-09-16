rule TTP_XOR_MULT_DOSStub_f02b {
  strings:
    $key_f02b = { a4 43 [2] d0 5b [2] 97 59 [2] d0 48 [2] 9e 44 [2] 92 4e [2] 85 45 [2] 9e 0b [2] a3 }

  condition:
    any of them
}