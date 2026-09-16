rule TTP_XOR_MULT_DOSStub_602d {
  strings:
    $key_602d = { 34 45 [2] 40 5d [2] 07 5f [2] 40 4e [2] 0e 42 [2] 02 48 [2] 15 43 [2] 0e 0d [2] 33 }

  condition:
    any of them
}