rule TTP_XOR_MULT_DOSStub_b76d {
  strings:
    $key_b76d = { e3 05 [2] 97 1d [2] d0 1f [2] 97 0e [2] d9 02 [2] d5 08 [2] c2 03 [2] d9 4d [2] e4 }

  condition:
    any of them
}