rule TTP_XOR_MULT_DOSStub_6b52 {
  strings:
    $key_6b52 = { 3f 3a [2] 4b 22 [2] 0c 20 [2] 4b 31 [2] 05 3d [2] 09 37 [2] 1e 3c [2] 05 72 [2] 38 }

  condition:
    any of them
}