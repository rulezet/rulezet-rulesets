rule TTP_XOR_MULT_DOSStub_0974 {
  strings:
    $key_0974 = { 5d 1c [2] 29 04 [2] 6e 06 [2] 29 17 [2] 67 1b [2] 6b 11 [2] 7c 1a [2] 67 54 [2] 5a }

  condition:
    any of them
}