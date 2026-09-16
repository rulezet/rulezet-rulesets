rule TTP_XOR_MULT_DOSStub_0052 {
  strings:
    $key_0052 = { 54 3a [2] 20 22 [2] 67 20 [2] 20 31 [2] 6e 3d [2] 62 37 [2] 75 3c [2] 6e 72 [2] 53 }

  condition:
    any of them
}