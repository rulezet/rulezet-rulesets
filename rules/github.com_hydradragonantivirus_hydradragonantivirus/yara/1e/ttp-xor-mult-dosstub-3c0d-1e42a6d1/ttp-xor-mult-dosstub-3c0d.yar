rule TTP_XOR_MULT_DOSStub_3c0d {
  strings:
    $key_3c0d = { 68 65 [2] 1c 7d [2] 5b 7f [2] 1c 6e [2] 52 62 [2] 5e 68 [2] 49 63 [2] 52 2d [2] 6f }

  condition:
    any of them
}