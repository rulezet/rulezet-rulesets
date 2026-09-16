rule TTP_XOR_MULT_DOSStub_1e1d {
  strings:
    $key_1e1d = { 4a 75 [2] 3e 6d [2] 79 6f [2] 3e 7e [2] 70 72 [2] 7c 78 [2] 6b 73 [2] 70 3d [2] 4d }

  condition:
    any of them
}