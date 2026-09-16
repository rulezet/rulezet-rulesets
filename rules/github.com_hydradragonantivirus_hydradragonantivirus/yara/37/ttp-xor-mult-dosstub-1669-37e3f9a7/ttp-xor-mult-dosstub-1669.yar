rule TTP_XOR_MULT_DOSStub_1669 {
  strings:
    $key_1669 = { 42 01 [2] 36 19 [2] 71 1b [2] 36 0a [2] 78 06 [2] 74 0c [2] 63 07 [2] 78 49 [2] 45 }

  condition:
    any of them
}