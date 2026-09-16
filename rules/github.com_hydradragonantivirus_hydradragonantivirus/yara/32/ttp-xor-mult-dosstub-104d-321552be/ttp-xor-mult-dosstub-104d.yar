rule TTP_XOR_MULT_DOSStub_104d {
  strings:
    $key_104d = { 44 25 [2] 30 3d [2] 77 3f [2] 30 2e [2] 7e 22 [2] 72 28 [2] 65 23 [2] 7e 6d [2] 43 }

  condition:
    any of them
}