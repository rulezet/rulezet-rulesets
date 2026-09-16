rule TTP_XOR_MULT_DOSStub_0d14 {
  strings:
    $key_0d14 = { 59 7c [2] 2d 64 [2] 6a 66 [2] 2d 77 [2] 63 7b [2] 6f 71 [2] 78 7a [2] 63 34 [2] 5e }

  condition:
    any of them
}