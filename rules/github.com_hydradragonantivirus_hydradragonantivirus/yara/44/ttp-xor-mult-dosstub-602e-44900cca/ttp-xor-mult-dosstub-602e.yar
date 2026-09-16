rule TTP_XOR_MULT_DOSStub_602e {
  strings:
    $key_602e = { 34 46 [2] 40 5e [2] 07 5c [2] 40 4d [2] 0e 41 [2] 02 4b [2] 15 40 [2] 0e 0e [2] 33 }

  condition:
    any of them
}