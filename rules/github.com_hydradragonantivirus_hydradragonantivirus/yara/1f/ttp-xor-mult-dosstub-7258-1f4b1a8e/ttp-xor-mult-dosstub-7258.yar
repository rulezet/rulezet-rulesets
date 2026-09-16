rule TTP_XOR_MULT_DOSStub_7258 {
  strings:
    $key_7258 = { 26 30 [2] 52 28 [2] 15 2a [2] 52 3b [2] 1c 37 [2] 10 3d [2] 07 36 [2] 1c 78 [2] 21 }

  condition:
    any of them
}