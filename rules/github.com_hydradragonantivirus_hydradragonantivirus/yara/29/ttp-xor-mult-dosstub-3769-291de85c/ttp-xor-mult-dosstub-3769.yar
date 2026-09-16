rule TTP_XOR_MULT_DOSStub_3769 {
  strings:
    $key_3769 = { 63 01 [2] 17 19 [2] 50 1b [2] 17 0a [2] 59 06 [2] 55 0c [2] 42 07 [2] 59 49 [2] 64 }

  condition:
    any of them
}