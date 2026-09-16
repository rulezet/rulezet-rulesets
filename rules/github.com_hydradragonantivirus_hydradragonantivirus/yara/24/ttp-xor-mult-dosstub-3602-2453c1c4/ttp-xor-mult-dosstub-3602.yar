rule TTP_XOR_MULT_DOSStub_3602 {
  strings:
    $key_3602 = { 62 6a [2] 16 72 [2] 51 70 [2] 16 61 [2] 58 6d [2] 54 67 [2] 43 6c [2] 58 22 [2] 65 }

  condition:
    any of them
}