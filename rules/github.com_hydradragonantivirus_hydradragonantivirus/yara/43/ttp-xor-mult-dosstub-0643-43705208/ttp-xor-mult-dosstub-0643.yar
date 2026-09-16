rule TTP_XOR_MULT_DOSStub_0643 {
  strings:
    $key_0643 = { 52 2b [2] 26 33 [2] 61 31 [2] 26 20 [2] 68 2c [2] 64 26 [2] 73 2d [2] 68 63 [2] 55 }

  condition:
    any of them
}