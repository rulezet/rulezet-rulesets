rule TTP_XOR_MULT_DOSStub_3662 {
  strings:
    $key_3662 = { 62 0a [2] 16 12 [2] 51 10 [2] 16 01 [2] 58 0d [2] 54 07 [2] 43 0c [2] 58 42 [2] 65 }

  condition:
    any of them
}