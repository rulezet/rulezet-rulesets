rule TTP_XOR_MULT_DOSStub_f4eb {
  strings:
    $key_f4eb = { a0 83 [2] d4 9b [2] 93 99 [2] d4 88 [2] 9a 84 [2] 96 8e [2] 81 85 [2] 9a cb [2] a7 }

  condition:
    any of them
}