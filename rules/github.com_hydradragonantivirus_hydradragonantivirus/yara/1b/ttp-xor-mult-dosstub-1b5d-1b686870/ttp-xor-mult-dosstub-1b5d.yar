rule TTP_XOR_MULT_DOSStub_1b5d {
  strings:
    $key_1b5d = { 4f 35 [2] 3b 2d [2] 7c 2f [2] 3b 3e [2] 75 32 [2] 79 38 [2] 6e 33 [2] 75 7d [2] 48 }

  condition:
    any of them
}