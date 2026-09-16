rule TTP_XOR_MULT_DOSStub_245d {
  strings:
    $key_245d = { 70 35 [2] 04 2d [2] 43 2f [2] 04 3e [2] 4a 32 [2] 46 38 [2] 51 33 [2] 4a 7d [2] 77 }

  condition:
    any of them
}