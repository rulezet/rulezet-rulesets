rule TTP_XOR_MULT_DOSStub_5164 {
  strings:
    $key_5164 = { 05 0c [2] 71 14 [2] 36 16 [2] 71 07 [2] 3f 0b [2] 33 01 [2] 24 0a [2] 3f 44 [2] 02 }

  condition:
    any of them
}