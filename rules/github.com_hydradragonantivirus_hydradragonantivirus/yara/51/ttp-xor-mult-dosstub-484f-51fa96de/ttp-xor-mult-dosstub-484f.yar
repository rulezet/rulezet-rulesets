rule TTP_XOR_MULT_DOSStub_484f {
  strings:
    $key_484f = { 1c 27 [2] 68 3f [2] 2f 3d [2] 68 2c [2] 26 20 [2] 2a 2a [2] 3d 21 [2] 26 6f [2] 1b }

  condition:
    any of them
}