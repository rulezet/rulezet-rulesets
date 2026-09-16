rule TTP_XOR_MULT_DOSStub_0a3d {
  strings:
    $key_0a3d = { 5e 55 [2] 2a 4d [2] 6d 4f [2] 2a 5e [2] 64 52 [2] 68 58 [2] 7f 53 [2] 64 1d [2] 59 }

  condition:
    any of them
}