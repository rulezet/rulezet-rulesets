rule TTP_XOR_MULT_DOSStub_7d74 {
  strings:
    $key_7d74 = { 29 1c [2] 5d 04 [2] 1a 06 [2] 5d 17 [2] 13 1b [2] 1f 11 [2] 08 1a [2] 13 54 [2] 2e }

  condition:
    any of them
}