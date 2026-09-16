rule TTP_XOR_MULT_DOSStub_7163 {
  strings:
    $key_7163 = { 25 0b [2] 51 13 [2] 16 11 [2] 51 00 [2] 1f 0c [2] 13 06 [2] 04 0d [2] 1f 43 [2] 22 }

  condition:
    any of them
}