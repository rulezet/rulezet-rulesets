rule TTP_XOR_MULT_DOSStub_0a1d {
  strings:
    $key_0a1d = { 5e 75 [2] 2a 6d [2] 6d 6f [2] 2a 7e [2] 64 72 [2] 68 78 [2] 7f 73 [2] 64 3d [2] 59 }

  condition:
    any of them
}