rule TTP_XOR_MULT_DOSStub_3264 {
  strings:
    $key_3264 = { 66 0c [2] 12 14 [2] 55 16 [2] 12 07 [2] 5c 0b [2] 50 01 [2] 47 0a [2] 5c 44 [2] 61 }

  condition:
    any of them
}