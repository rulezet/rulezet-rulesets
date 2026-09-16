rule TTP_XOR_MULT_DOSStub_5375 {
  strings:
    $key_5375 = { 07 1d [2] 73 05 [2] 34 07 [2] 73 16 [2] 3d 1a [2] 31 10 [2] 26 1b [2] 3d 55 [2] 00 }

  condition:
    any of them
}