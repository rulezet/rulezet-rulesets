rule TTP_XOR_MULT_DOSStub_7e52 {
  strings:
    $key_7e52 = { 2a 3a [2] 5e 22 [2] 19 20 [2] 5e 31 [2] 10 3d [2] 1c 37 [2] 0b 3c [2] 10 72 [2] 2d }

  condition:
    any of them
}