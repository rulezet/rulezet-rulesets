rule TTP_XOR_MULT_DOSStub_7c3d {
  strings:
    $key_7c3d = { 28 55 [2] 5c 4d [2] 1b 4f [2] 5c 5e [2] 12 52 [2] 1e 58 [2] 09 53 [2] 12 1d [2] 2f }

  condition:
    any of them
}