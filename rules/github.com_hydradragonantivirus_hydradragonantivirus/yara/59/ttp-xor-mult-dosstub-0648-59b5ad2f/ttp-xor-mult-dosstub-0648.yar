rule TTP_XOR_MULT_DOSStub_0648 {
  strings:
    $key_0648 = { 52 20 [2] 26 38 [2] 61 3a [2] 26 2b [2] 68 27 [2] 64 2d [2] 73 26 [2] 68 68 [2] 55 }

  condition:
    any of them
}