rule TTP_XOR_MULT_DOSStub_0d05 {
  strings:
    $key_0d05 = { 59 6d [2] 2d 75 [2] 6a 77 [2] 2d 66 [2] 63 6a [2] 6f 60 [2] 78 6b [2] 63 25 [2] 5e }

  condition:
    any of them
}