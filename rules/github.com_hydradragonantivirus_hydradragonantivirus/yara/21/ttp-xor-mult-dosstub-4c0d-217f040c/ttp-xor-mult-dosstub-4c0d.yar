rule TTP_XOR_MULT_DOSStub_4c0d {
  strings:
    $key_4c0d = { 18 65 [2] 6c 7d [2] 2b 7f [2] 6c 6e [2] 22 62 [2] 2e 68 [2] 39 63 [2] 22 2d [2] 1f }

  condition:
    any of them
}