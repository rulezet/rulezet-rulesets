rule TTP_XOR_MULT_DOSStub_775d {
  strings:
    $key_775d = { 23 35 [2] 57 2d [2] 10 2f [2] 57 3e [2] 19 32 [2] 15 38 [2] 02 33 [2] 19 7d [2] 24 }

  condition:
    any of them
}