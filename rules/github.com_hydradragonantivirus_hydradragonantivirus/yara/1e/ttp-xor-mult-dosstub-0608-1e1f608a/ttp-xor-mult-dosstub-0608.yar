rule TTP_XOR_MULT_DOSStub_0608 {
  strings:
    $key_0608 = { 52 60 [2] 26 78 [2] 61 7a [2] 26 6b [2] 68 67 [2] 64 6d [2] 73 66 [2] 68 28 [2] 55 }

  condition:
    any of them
}