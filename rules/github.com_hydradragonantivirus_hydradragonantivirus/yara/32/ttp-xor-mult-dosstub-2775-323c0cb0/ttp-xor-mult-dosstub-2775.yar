rule TTP_XOR_MULT_DOSStub_2775 {
  strings:
    $key_2775 = { 73 1d [2] 07 05 [2] 40 07 [2] 07 16 [2] 49 1a [2] 45 10 [2] 52 1b [2] 49 55 [2] 74 }

  condition:
    any of them
}