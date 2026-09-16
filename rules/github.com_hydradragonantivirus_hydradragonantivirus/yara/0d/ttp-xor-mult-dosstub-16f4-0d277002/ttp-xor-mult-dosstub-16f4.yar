rule TTP_XOR_MULT_DOSStub_16f4 {
  strings:
    $key_16f4 = { 42 9c [2] 36 84 [2] 71 86 [2] 36 97 [2] 78 9b [2] 74 91 [2] 63 9a [2] 78 d4 [2] 45 }

  condition:
    any of them
}