rule TTP_XOR_MULT_DOSStub_0d54 {
  strings:
    $key_0d54 = { 59 3c [2] 2d 24 [2] 6a 26 [2] 2d 37 [2] 63 3b [2] 6f 31 [2] 78 3a [2] 63 74 [2] 5e }

  condition:
    any of them
}