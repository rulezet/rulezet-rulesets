rule TTP_XOR_MULT_DOSStub_f4ee {
  strings:
    $key_f4ee = { a0 86 [2] d4 9e [2] 93 9c [2] d4 8d [2] 9a 81 [2] 96 8b [2] 81 80 [2] 9a ce [2] a7 }

  condition:
    any of them
}