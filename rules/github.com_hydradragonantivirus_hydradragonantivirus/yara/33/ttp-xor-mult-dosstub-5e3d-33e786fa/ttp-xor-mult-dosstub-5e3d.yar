rule TTP_XOR_MULT_DOSStub_5e3d {
  strings:
    $key_5e3d = { 0a 55 [2] 7e 4d [2] 39 4f [2] 7e 5e [2] 30 52 [2] 3c 58 [2] 2b 53 [2] 30 1d [2] 0d }

  condition:
    any of them
}