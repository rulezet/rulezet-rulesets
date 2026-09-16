rule TTP_XOR_MULT_DOSStub_4069 {
  strings:
    $key_4069 = { 14 01 [2] 60 19 [2] 27 1b [2] 60 0a [2] 2e 06 [2] 22 0c [2] 35 07 [2] 2e 49 [2] 13 }

  condition:
    any of them
}