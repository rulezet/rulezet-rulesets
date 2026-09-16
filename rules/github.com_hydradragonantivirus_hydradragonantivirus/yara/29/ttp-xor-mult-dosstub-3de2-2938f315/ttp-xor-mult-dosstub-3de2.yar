rule TTP_XOR_MULT_DOSStub_3de2 {
  strings:
    $key_3de2 = { 69 8a [2] 1d 92 [2] 5a 90 [2] 1d 81 [2] 53 8d [2] 5f 87 [2] 48 8c [2] 53 c2 [2] 6e }

  condition:
    any of them
}