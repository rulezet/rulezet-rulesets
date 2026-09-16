rule TTP_XOR_MULT_DOSStub_0a58 {
  strings:
    $key_0a58 = { 5e 30 [2] 2a 28 [2] 6d 2a [2] 2a 3b [2] 64 37 [2] 68 3d [2] 7f 36 [2] 64 78 [2] 59 }

  condition:
    any of them
}