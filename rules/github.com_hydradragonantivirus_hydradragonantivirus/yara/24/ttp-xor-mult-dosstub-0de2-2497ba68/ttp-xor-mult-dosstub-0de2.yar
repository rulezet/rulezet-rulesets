rule TTP_XOR_MULT_DOSStub_0de2 {
  strings:
    $key_0de2 = { 59 8a [2] 2d 92 [2] 6a 90 [2] 2d 81 [2] 63 8d [2] 6f 87 [2] 78 8c [2] 63 c2 [2] 5e }

  condition:
    any of them
}