rule TTP_XOR_MULT_DOSStub_2769 {
  strings:
    $key_2769 = { 73 01 [2] 07 19 [2] 40 1b [2] 07 0a [2] 49 06 [2] 45 0c [2] 52 07 [2] 49 49 [2] 74 }

  condition:
    any of them
}