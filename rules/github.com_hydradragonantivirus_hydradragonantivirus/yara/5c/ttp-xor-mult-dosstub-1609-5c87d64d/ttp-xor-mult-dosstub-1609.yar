rule TTP_XOR_MULT_DOSStub_1609 {
  strings:
    $key_1609 = { 42 61 [2] 36 79 [2] 71 7b [2] 36 6a [2] 78 66 [2] 74 6c [2] 63 67 [2] 78 29 [2] 45 }

  condition:
    any of them
}