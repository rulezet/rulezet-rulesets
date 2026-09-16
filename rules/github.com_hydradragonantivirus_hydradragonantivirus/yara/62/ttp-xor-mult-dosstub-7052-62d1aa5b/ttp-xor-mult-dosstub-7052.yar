rule TTP_XOR_MULT_DOSStub_7052 {
  strings:
    $key_7052 = { 24 3a [2] 50 22 [2] 17 20 [2] 50 31 [2] 1e 3d [2] 12 37 [2] 05 3c [2] 1e 72 [2] 23 }

  condition:
    any of them
}