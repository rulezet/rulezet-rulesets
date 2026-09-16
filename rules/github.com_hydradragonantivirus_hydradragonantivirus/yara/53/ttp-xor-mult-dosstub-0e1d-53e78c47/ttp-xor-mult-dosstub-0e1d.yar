rule TTP_XOR_MULT_DOSStub_0e1d {
  strings:
    $key_0e1d = { 5a 75 [2] 2e 6d [2] 69 6f [2] 2e 7e [2] 60 72 [2] 6c 78 [2] 7b 73 [2] 60 3d [2] 5d }

  condition:
    any of them
}