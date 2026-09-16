rule TTP_XOR_MULT_DOSStub_f90d {
  strings:
    $key_f90d = { ad 65 [2] d9 7d [2] 9e 7f [2] d9 6e [2] 97 62 [2] 9b 68 [2] 8c 63 [2] 97 2d [2] aa }

  condition:
    any of them
}