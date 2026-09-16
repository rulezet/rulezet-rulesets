rule TTP_XOR_MULT_DOSStub_f12c {
  strings:
    $key_f12c = { a5 44 [2] d1 5c [2] 96 5e [2] d1 4f [2] 9f 43 [2] 93 49 [2] 84 42 [2] 9f 0c [2] a2 }

  condition:
    any of them
}