rule TTP_XOR_MULT_DOSStub_0453 {
  strings:
    $key_0453 = { 50 3b [2] 24 23 [2] 63 21 [2] 24 30 [2] 6a 3c [2] 66 36 [2] 71 3d [2] 6a 73 [2] 57 }

  condition:
    any of them
}