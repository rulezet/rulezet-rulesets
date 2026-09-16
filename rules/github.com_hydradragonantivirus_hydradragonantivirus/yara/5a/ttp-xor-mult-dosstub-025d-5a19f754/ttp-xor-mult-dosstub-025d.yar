rule TTP_XOR_MULT_DOSStub_025d {
  strings:
    $key_025d = { 56 35 [2] 22 2d [2] 65 2f [2] 22 3e [2] 6c 32 [2] 60 38 [2] 77 33 [2] 6c 7d [2] 51 }

  condition:
    any of them
}