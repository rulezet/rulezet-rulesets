rule TTP_XOR_MULT_DOSStub_2e52 {
  strings:
    $key_2e52 = { 7a 3a [2] 0e 22 [2] 49 20 [2] 0e 31 [2] 40 3d [2] 4c 37 [2] 5b 3c [2] 40 72 [2] 7d }

  condition:
    any of them
}