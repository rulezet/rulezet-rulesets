rule TTP_XOR_MULT_DOSStub_01e5 {
  strings:
    $key_01e5 = { 55 8d [2] 21 95 [2] 66 97 [2] 21 86 [2] 6f 8a [2] 63 80 [2] 74 8b [2] 6f c5 [2] 52 }

  condition:
    any of them
}