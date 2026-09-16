rule TTP_XOR_MULT_DOSStub_27e8 {
  strings:
    $key_27e8 = { 73 80 [2] 07 98 [2] 40 9a [2] 07 8b [2] 49 87 [2] 45 8d [2] 52 86 [2] 49 c8 [2] 74 }

  condition:
    any of them
}