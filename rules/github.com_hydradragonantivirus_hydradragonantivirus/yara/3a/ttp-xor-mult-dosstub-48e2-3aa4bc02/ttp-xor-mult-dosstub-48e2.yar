rule TTP_XOR_MULT_DOSStub_48e2 {
  strings:
    $key_48e2 = { 1c 8a [2] 68 92 [2] 2f 90 [2] 68 81 [2] 26 8d [2] 2a 87 [2] 3d 8c [2] 26 c2 [2] 1b }

  condition:
    any of them
}