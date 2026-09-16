rule TTP_XOR_MULT_DOSStub_412d {
  strings:
    $key_412d = { 15 45 [2] 61 5d [2] 26 5f [2] 61 4e [2] 2f 42 [2] 23 48 [2] 34 43 [2] 2f 0d [2] 12 }

  condition:
    any of them
}