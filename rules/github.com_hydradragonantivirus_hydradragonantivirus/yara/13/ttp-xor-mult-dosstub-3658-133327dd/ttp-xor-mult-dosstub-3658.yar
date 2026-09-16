rule TTP_XOR_MULT_DOSStub_3658 {
  strings:
    $key_3658 = { 62 30 [2] 16 28 [2] 51 2a [2] 16 3b [2] 58 37 [2] 54 3d [2] 43 36 [2] 58 78 [2] 65 }

  condition:
    any of them
}