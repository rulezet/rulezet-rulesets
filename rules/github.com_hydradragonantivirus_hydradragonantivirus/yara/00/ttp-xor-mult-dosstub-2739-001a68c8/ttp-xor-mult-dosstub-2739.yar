rule TTP_XOR_MULT_DOSStub_2739 {
  strings:
    $key_2739 = { 73 51 [2] 07 49 [2] 40 4b [2] 07 5a [2] 49 56 [2] 45 5c [2] 52 57 [2] 49 19 [2] 74 }

  condition:
    any of them
}