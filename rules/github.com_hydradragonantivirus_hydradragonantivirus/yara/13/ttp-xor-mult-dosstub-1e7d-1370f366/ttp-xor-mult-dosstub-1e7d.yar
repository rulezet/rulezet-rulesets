rule TTP_XOR_MULT_DOSStub_1e7d {
  strings:
    $key_1e7d = { 4a 15 [2] 3e 0d [2] 79 0f [2] 3e 1e [2] 70 12 [2] 7c 18 [2] 6b 13 [2] 70 5d [2] 4d }

  condition:
    any of them
}