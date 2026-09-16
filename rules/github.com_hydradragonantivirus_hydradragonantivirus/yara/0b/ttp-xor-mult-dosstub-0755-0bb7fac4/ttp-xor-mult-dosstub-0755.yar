rule TTP_XOR_MULT_DOSStub_0755 {
  strings:
    $key_0755 = { 53 3d [2] 27 25 [2] 60 27 [2] 27 36 [2] 69 3a [2] 65 30 [2] 72 3b [2] 69 75 [2] 54 }

  condition:
    any of them
}