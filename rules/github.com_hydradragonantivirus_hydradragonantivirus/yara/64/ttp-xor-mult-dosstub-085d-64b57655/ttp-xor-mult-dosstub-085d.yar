rule TTP_XOR_MULT_DOSStub_085d {
  strings:
    $key_085d = { 5c 35 [2] 28 2d [2] 6f 2f [2] 28 3e [2] 66 32 [2] 6a 38 [2] 7d 33 [2] 66 7d [2] 5b }

  condition:
    any of them
}