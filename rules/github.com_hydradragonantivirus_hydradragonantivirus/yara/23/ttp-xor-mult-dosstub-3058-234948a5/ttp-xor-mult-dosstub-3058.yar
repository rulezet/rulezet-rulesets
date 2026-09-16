rule TTP_XOR_MULT_DOSStub_3058 {
  strings:
    $key_3058 = { 64 30 [2] 10 28 [2] 57 2a [2] 10 3b [2] 5e 37 [2] 52 3d [2] 45 36 [2] 5e 78 [2] 63 }

  condition:
    any of them
}