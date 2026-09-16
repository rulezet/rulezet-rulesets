rule TTP_XOR_MULT_DOSStub_263e {
  strings:
    $key_263e = { 72 56 [2] 06 4e [2] 41 4c [2] 06 5d [2] 48 51 [2] 44 5b [2] 53 50 [2] 48 1e [2] 75 }

  condition:
    any of them
}