rule TTP_XOR_MULT_DOSStub_4d74 {
  strings:
    $key_4d74 = { 19 1c [2] 6d 04 [2] 2a 06 [2] 6d 17 [2] 23 1b [2] 2f 11 [2] 38 1a [2] 23 54 [2] 1e }

  condition:
    any of them
}