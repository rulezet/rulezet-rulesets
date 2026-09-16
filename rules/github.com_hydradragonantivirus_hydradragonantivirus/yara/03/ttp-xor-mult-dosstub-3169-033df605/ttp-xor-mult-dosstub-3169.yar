rule TTP_XOR_MULT_DOSStub_3169 {
  strings:
    $key_3169 = { 65 01 [2] 11 19 [2] 56 1b [2] 11 0a [2] 5f 06 [2] 53 0c [2] 44 07 [2] 5f 49 [2] 62 }

  condition:
    any of them
}