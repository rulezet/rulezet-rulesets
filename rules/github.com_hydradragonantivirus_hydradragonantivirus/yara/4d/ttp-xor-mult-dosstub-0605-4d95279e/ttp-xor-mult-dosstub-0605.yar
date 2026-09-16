rule TTP_XOR_MULT_DOSStub_0605 {
  strings:
    $key_0605 = { 52 6d [2] 26 75 [2] 61 77 [2] 26 66 [2] 68 6a [2] 64 60 [2] 73 6b [2] 68 25 [2] 55 }

  condition:
    any of them
}