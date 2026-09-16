rule TTP_XOR_MULT_DOSStub_4724 {
  strings:
    $key_4724 = { 13 4c [2] 67 54 [2] 20 56 [2] 67 47 [2] 29 4b [2] 25 41 [2] 32 4a [2] 29 04 [2] 14 }

  condition:
    any of them
}