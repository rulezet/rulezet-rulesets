rule TTP_XOR_MULT_DOSStub_27e9 {
  strings:
    $key_27e9 = { 73 81 [2] 07 99 [2] 40 9b [2] 07 8a [2] 49 86 [2] 45 8c [2] 52 87 [2] 49 c9 [2] 74 }

  condition:
    any of them
}