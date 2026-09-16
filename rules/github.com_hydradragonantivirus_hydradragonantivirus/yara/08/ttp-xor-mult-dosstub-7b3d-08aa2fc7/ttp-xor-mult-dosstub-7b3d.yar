rule TTP_XOR_MULT_DOSStub_7b3d {
  strings:
    $key_7b3d = { 2f 55 [2] 5b 4d [2] 1c 4f [2] 5b 5e [2] 15 52 [2] 19 58 [2] 0e 53 [2] 15 1d [2] 28 }

  condition:
    any of them
}