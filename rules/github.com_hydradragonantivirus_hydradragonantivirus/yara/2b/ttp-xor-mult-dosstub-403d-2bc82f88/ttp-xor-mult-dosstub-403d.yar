rule TTP_XOR_MULT_DOSStub_403d {
  strings:
    $key_403d = { 14 55 [2] 60 4d [2] 27 4f [2] 60 5e [2] 2e 52 [2] 22 58 [2] 35 53 [2] 2e 1d [2] 13 }

  condition:
    any of them
}