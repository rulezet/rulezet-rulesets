rule TTP_XOR_MULT_DOSStub_4b52 {
  strings:
    $key_4b52 = { 1f 3a [2] 6b 22 [2] 2c 20 [2] 6b 31 [2] 25 3d [2] 29 37 [2] 3e 3c [2] 25 72 [2] 18 }

  condition:
    any of them
}