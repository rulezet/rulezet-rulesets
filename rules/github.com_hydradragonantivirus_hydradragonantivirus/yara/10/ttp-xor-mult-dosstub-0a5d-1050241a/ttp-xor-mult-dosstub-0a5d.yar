rule TTP_XOR_MULT_DOSStub_0a5d {
  strings:
    $key_0a5d = { 5e 35 [2] 2a 2d [2] 6d 2f [2] 2a 3e [2] 64 32 [2] 68 38 [2] 7f 33 [2] 64 7d [2] 59 }

  condition:
    any of them
}