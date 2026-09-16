rule TTP_XOR_MULT_DOSStub_3b3d {
  strings:
    $key_3b3d = { 6f 55 [2] 1b 4d [2] 5c 4f [2] 1b 5e [2] 55 52 [2] 59 58 [2] 4e 53 [2] 55 1d [2] 68 }

  condition:
    any of them
}