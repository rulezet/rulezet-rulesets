rule TTP_XOR_MULT_DOSStub_4358 {
  strings:
    $key_4358 = { 17 30 [2] 63 28 [2] 24 2a [2] 63 3b [2] 2d 37 [2] 21 3d [2] 36 36 [2] 2d 78 [2] 10 }

  condition:
    any of them
}