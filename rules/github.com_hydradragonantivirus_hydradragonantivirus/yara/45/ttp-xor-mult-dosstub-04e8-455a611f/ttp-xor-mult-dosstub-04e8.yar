rule TTP_XOR_MULT_DOSStub_04e8 {
  strings:
    $key_04e8 = { 50 80 [2] 24 98 [2] 63 9a [2] 24 8b [2] 6a 87 [2] 66 8d [2] 71 86 [2] 6a c8 [2] 57 }

  condition:
    any of them
}