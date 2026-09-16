rule TTP_XOR_MULT_DOSStub_5b3d {
  strings:
    $key_5b3d = { 0f 55 [2] 7b 4d [2] 3c 4f [2] 7b 5e [2] 35 52 [2] 39 58 [2] 2e 53 [2] 35 1d [2] 08 }

  condition:
    any of them
}