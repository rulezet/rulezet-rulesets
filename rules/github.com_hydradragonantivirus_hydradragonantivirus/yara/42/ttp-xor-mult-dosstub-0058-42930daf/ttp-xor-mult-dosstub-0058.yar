rule TTP_XOR_MULT_DOSStub_0058 {
  strings:
    $key_0058 = { 54 30 [2] 20 28 [2] 67 2a [2] 20 3b [2] 6e 37 [2] 62 3d [2] 75 36 [2] 6e 78 [2] 53 }

  condition:
    any of them
}