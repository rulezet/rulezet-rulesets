rule TTP_XOR_MULT_DOSStub_3774 {
  strings:
    $key_3774 = { 63 1c [2] 17 04 [2] 50 06 [2] 17 17 [2] 59 1b [2] 55 11 [2] 42 1a [2] 59 54 [2] 64 }

  condition:
    any of them
}