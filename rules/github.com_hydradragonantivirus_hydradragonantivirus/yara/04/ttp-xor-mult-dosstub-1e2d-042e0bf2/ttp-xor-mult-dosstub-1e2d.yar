rule TTP_XOR_MULT_DOSStub_1e2d {
  strings:
    $key_1e2d = { 4a 45 [2] 3e 5d [2] 79 5f [2] 3e 4e [2] 70 42 [2] 7c 48 [2] 6b 43 [2] 70 0d [2] 4d }

  condition:
    any of them
}