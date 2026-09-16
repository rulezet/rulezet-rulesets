rule TTP_XOR_MULT_DOSStub_f42b {
  strings:
    $key_f42b = { a0 43 [2] d4 5b [2] 93 59 [2] d4 48 [2] 9a 44 [2] 96 4e [2] 81 45 [2] 9a 0b [2] a7 }

  condition:
    any of them
}