rule TTP_XOR_MULT_DOSStub_3e52 {
  strings:
    $key_3e52 = { 6a 3a [2] 1e 22 [2] 59 20 [2] 1e 31 [2] 50 3d [2] 5c 37 [2] 4b 3c [2] 50 72 [2] 6d }

  condition:
    any of them
}