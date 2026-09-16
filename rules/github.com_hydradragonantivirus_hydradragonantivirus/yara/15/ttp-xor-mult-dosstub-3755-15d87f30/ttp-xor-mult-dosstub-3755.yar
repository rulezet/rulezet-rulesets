rule TTP_XOR_MULT_DOSStub_3755 {
  strings:
    $key_3755 = { 63 3d [2] 17 25 [2] 50 27 [2] 17 36 [2] 59 3a [2] 55 30 [2] 42 3b [2] 59 75 [2] 64 }

  condition:
    any of them
}