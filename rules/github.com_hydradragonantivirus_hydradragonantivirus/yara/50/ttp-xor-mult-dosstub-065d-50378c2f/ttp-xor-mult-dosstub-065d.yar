rule TTP_XOR_MULT_DOSStub_065d {
  strings:
    $key_065d = { 52 35 [2] 26 2d [2] 61 2f [2] 26 3e [2] 68 32 [2] 64 38 [2] 73 33 [2] 68 7d [2] 55 }

  condition:
    any of them
}