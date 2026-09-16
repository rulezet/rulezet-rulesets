rule TTP_XOR_MULT_DOSStub_f4fc {
  strings:
    $key_f4fc = { a0 94 [2] d4 8c [2] 93 8e [2] d4 9f [2] 9a 93 [2] 96 99 [2] 81 92 [2] 9a dc [2] a7 }

  condition:
    any of them
}