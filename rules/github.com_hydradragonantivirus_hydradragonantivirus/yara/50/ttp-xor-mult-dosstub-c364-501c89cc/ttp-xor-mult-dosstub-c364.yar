rule TTP_XOR_MULT_DOSStub_c364 {
  strings:
    $key_c364 = { 97 0c [2] e3 14 [2] a4 16 [2] e3 07 [2] ad 0b [2] a1 01 [2] b6 0a [2] ad 44 [2] 90 }

  condition:
    any of them
}