rule TTP_XOR_MULT_DOSStub_1e0d {
  strings:
    $key_1e0d = { 4a 65 [2] 3e 7d [2] 79 7f [2] 3e 6e [2] 70 62 [2] 7c 68 [2] 6b 63 [2] 70 2d [2] 4d }

  condition:
    any of them
}