rule TTP_XOR_MULT_DOSStub_0704 {
  strings:
    $key_0704 = { 53 6c [2] 27 74 [2] 60 76 [2] 27 67 [2] 69 6b [2] 65 61 [2] 72 6a [2] 69 24 [2] 54 }

  condition:
    any of them
}