rule TTP_XOR_MULT_DOSStub_022d {
  strings:
    $key_022d = { 56 45 [2] 22 5d [2] 65 5f [2] 22 4e [2] 6c 42 [2] 60 48 [2] 77 43 [2] 6c 0d [2] 51 }

  condition:
    any of them
}