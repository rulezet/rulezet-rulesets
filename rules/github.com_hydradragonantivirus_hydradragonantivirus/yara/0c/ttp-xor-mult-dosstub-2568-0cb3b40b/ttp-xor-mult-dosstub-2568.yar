rule TTP_XOR_MULT_DOSStub_2568 {
  strings:
    $key_2568 = { 71 00 [2] 05 18 [2] 42 1a [2] 05 0b [2] 4b 07 [2] 47 0d [2] 50 06 [2] 4b 48 [2] 76 }

  condition:
    any of them
}