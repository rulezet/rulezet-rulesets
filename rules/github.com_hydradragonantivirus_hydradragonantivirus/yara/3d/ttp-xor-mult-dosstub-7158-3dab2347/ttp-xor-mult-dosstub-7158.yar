rule TTP_XOR_MULT_DOSStub_7158 {
  strings:
    $key_7158 = { 25 30 [2] 51 28 [2] 16 2a [2] 51 3b [2] 1f 37 [2] 13 3d [2] 04 36 [2] 1f 78 [2] 22 }

  condition:
    any of them
}