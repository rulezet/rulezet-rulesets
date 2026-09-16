rule TTP_XOR_MULT_DOSStub_553d {
  strings:
    $key_553d = { 01 55 [2] 75 4d [2] 32 4f [2] 75 5e [2] 3b 52 [2] 37 58 [2] 20 53 [2] 3b 1d [2] 06 }

  condition:
    any of them
}