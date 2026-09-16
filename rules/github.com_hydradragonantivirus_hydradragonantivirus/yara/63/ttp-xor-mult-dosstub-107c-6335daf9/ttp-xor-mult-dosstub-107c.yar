rule TTP_XOR_MULT_DOSStub_107c {
  strings:
    $key_107c = { 44 14 [2] 30 0c [2] 77 0e [2] 30 1f [2] 7e 13 [2] 72 19 [2] 65 12 [2] 7e 5c [2] 43 }

  condition:
    any of them
}