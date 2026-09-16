rule TTP_XOR_MULT_DOSStub_0a4d {
  strings:
    $key_0a4d = { 5e 25 [2] 2a 3d [2] 6d 3f [2] 2a 2e [2] 64 22 [2] 68 28 [2] 7f 23 [2] 64 6d [2] 59 }

  condition:
    any of them
}