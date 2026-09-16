rule TTP_XOR_MULT_DOSStub_014d {
  strings:
    $key_014d = { 55 25 [2] 21 3d [2] 66 3f [2] 21 2e [2] 6f 22 [2] 63 28 [2] 74 23 [2] 6f 6d [2] 52 }

  condition:
    any of them
}