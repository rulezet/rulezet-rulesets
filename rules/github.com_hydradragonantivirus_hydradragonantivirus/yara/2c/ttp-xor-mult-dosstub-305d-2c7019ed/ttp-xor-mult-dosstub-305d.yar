rule TTP_XOR_MULT_DOSStub_305d {
  strings:
    $key_305d = { 64 35 [2] 10 2d [2] 57 2f [2] 10 3e [2] 5e 32 [2] 52 38 [2] 45 33 [2] 5e 7d [2] 63 }

  condition:
    any of them
}