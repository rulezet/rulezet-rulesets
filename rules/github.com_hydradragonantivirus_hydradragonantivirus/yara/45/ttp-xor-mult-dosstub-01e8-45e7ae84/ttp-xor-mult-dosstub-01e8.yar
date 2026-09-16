rule TTP_XOR_MULT_DOSStub_01e8 {
  strings:
    $key_01e8 = { 55 80 [2] 21 98 [2] 66 9a [2] 21 8b [2] 6f 87 [2] 63 8d [2] 74 86 [2] 6f c8 [2] 52 }

  condition:
    any of them
}