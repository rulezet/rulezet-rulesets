rule TTP_XOR_MULT_DOSStub_f95d {
  strings:
    $key_f95d = { ad 35 [2] d9 2d [2] 9e 2f [2] d9 3e [2] 97 32 [2] 9b 38 [2] 8c 33 [2] 97 7d [2] aa }

  condition:
    any of them
}