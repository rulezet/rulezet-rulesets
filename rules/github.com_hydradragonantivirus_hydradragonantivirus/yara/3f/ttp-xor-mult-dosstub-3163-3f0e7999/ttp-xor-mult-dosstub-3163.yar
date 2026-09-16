rule TTP_XOR_MULT_DOSStub_3163 {
  strings:
    $key_3163 = { 65 0b [2] 11 13 [2] 56 11 [2] 11 00 [2] 5f 0c [2] 53 06 [2] 44 0d [2] 5f 43 [2] 62 }

  condition:
    any of them
}