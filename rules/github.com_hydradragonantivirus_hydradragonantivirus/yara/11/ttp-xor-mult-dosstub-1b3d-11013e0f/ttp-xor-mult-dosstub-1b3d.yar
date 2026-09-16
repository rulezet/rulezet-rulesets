rule TTP_XOR_MULT_DOSStub_1b3d {
  strings:
    $key_1b3d = { 4f 55 [2] 3b 4d [2] 7c 4f [2] 3b 5e [2] 75 52 [2] 79 58 [2] 6e 53 [2] 75 1d [2] 48 }

  condition:
    any of them
}