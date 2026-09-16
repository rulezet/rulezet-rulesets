rule TTP_XOR_MULT_DOSStub_36e8 {
  strings:
    $key_36e8 = { 62 80 [2] 16 98 [2] 51 9a [2] 16 8b [2] 58 87 [2] 54 8d [2] 43 86 [2] 58 c8 [2] 65 }

  condition:
    any of them
}