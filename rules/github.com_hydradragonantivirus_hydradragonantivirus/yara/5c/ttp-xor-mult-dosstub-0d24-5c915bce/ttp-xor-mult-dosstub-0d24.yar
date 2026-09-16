rule TTP_XOR_MULT_DOSStub_0d24 {
  strings:
    $key_0d24 = { 59 4c [2] 2d 54 [2] 6a 56 [2] 2d 47 [2] 63 4b [2] 6f 41 [2] 78 4a [2] 63 04 [2] 5e }

  condition:
    any of them
}