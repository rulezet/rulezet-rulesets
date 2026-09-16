rule TTP_XOR_MULT_DOSStub_0d74 {
  strings:
    $key_0d74 = { 59 1c [2] 2d 04 [2] 6a 06 [2] 2d 17 [2] 63 1b [2] 6f 11 [2] 78 1a [2] 63 54 [2] 5e }

  condition:
    any of them
}