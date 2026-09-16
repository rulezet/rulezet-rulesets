rule TTP_XOR_MULT_DOSStub_0d5d {
  strings:
    $key_0d5d = { 59 35 [2] 2d 2d [2] 6a 2f [2] 2d 3e [2] 63 32 [2] 6f 38 [2] 78 33 [2] 63 7d [2] 5e }

  condition:
    any of them
}