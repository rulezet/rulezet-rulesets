rule TTP_XOR_MULT_DOSStub_0de9 {
  strings:
    $key_0de9 = { 59 81 [2] 2d 99 [2] 6a 9b [2] 2d 8a [2] 63 86 [2] 6f 8c [2] 78 87 [2] 63 c9 [2] 5e }

  condition:
    any of them
}