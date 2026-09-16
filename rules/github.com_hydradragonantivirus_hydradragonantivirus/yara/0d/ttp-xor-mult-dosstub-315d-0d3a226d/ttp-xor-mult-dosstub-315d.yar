rule TTP_XOR_MULT_DOSStub_315d {
  strings:
    $key_315d = { 65 35 [2] 11 2d [2] 56 2f [2] 11 3e [2] 5f 32 [2] 53 38 [2] 44 33 [2] 5f 7d [2] 62 }

  condition:
    any of them
}