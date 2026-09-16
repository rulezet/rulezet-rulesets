rule TTP_XOR_MULT_DOSStub_575d {
  strings:
    $key_575d = { 03 35 [2] 77 2d [2] 30 2f [2] 77 3e [2] 39 32 [2] 35 38 [2] 22 33 [2] 39 7d [2] 04 }

  condition:
    any of them
}