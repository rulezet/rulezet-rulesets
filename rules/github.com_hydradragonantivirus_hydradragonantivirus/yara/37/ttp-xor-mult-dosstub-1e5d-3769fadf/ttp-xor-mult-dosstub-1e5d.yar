rule TTP_XOR_MULT_DOSStub_1e5d {
  strings:
    $key_1e5d = { 4a 35 [2] 3e 2d [2] 79 2f [2] 3e 3e [2] 70 32 [2] 7c 38 [2] 6b 33 [2] 70 7d [2] 4d }

  condition:
    any of them
}