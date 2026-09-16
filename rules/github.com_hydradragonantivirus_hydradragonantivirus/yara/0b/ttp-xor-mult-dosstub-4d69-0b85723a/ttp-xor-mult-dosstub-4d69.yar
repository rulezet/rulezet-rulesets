rule TTP_XOR_MULT_DOSStub_4d69 {
  strings:
    $key_4d69 = { 19 01 [2] 6d 19 [2] 2a 1b [2] 6d 0a [2] 23 06 [2] 2f 0c [2] 38 07 [2] 23 49 [2] 1e }

  condition:
    any of them
}