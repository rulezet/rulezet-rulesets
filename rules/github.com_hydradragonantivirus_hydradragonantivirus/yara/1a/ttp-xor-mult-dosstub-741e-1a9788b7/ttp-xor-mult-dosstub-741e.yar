rule TTP_XOR_MULT_DOSStub_741e {
  strings:
    $key_741e = { 20 76 [2] 54 6e [2] 13 6c [2] 54 7d [2] 1a 71 [2] 16 7b [2] 01 70 [2] 1a 3e [2] 27 }

  condition:
    any of them
}