rule TTP_XOR_MULT_DOSStub_2764 {
  strings:
    $key_2764 = { 73 0c [2] 07 14 [2] 40 16 [2] 07 07 [2] 49 0b [2] 45 01 [2] 52 0a [2] 49 44 [2] 74 }

  condition:
    any of them
}