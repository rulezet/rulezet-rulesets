rule TTP_XOR_MULT_DOSStub_023d {
  strings:
    $key_023d = { 56 55 [2] 22 4d [2] 65 4f [2] 22 5e [2] 6c 52 [2] 60 58 [2] 77 53 [2] 6c 1d [2] 51 }

  condition:
    any of them
}