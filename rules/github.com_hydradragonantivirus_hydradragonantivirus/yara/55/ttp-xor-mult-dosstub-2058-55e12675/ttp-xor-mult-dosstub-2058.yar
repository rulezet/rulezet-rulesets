rule TTP_XOR_MULT_DOSStub_2058 {
  strings:
    $key_2058 = { 74 30 [2] 00 28 [2] 47 2a [2] 00 3b [2] 4e 37 [2] 42 3d [2] 55 36 [2] 4e 78 [2] 73 }

  condition:
    any of them
}