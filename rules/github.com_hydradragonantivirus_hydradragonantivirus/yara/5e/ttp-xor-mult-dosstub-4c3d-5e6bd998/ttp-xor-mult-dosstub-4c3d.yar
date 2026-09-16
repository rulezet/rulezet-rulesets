rule TTP_XOR_MULT_DOSStub_4c3d {
  strings:
    $key_4c3d = { 18 55 [2] 6c 4d [2] 2b 4f [2] 6c 5e [2] 22 52 [2] 2e 58 [2] 39 53 [2] 22 1d [2] 1f }

  condition:
    any of them
}