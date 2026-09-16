rule TTP_XOR_MULT_DOSStub_5b1d {
  strings:
    $key_5b1d = { 0f 75 [2] 7b 6d [2] 3c 6f [2] 7b 7e [2] 35 72 [2] 39 78 [2] 2e 73 [2] 35 3d [2] 08 }

  condition:
    any of them
}