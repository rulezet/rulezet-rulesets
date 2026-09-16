rule TTP_XOR_MULT_DOSStub_63f5 {
  strings:
    $key_63f5 = { 37 9d [2] 43 85 [2] 04 87 [2] 43 96 [2] 0d 9a [2] 01 90 [2] 16 9b [2] 0d d5 [2] 30 }

  condition:
    any of them
}