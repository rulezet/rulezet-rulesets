rule TTP_XOR_MULT_DOSStub_711e {
  strings:
    $key_711e = { 25 76 [2] 51 6e [2] 16 6c [2] 51 7d [2] 1f 71 [2] 13 7b [2] 04 70 [2] 1f 3e [2] 22 }

  condition:
    any of them
}