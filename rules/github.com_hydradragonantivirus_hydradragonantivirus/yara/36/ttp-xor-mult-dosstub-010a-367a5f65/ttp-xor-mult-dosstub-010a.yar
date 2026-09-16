rule TTP_XOR_MULT_DOSStub_010a {
  strings:
    $key_010a = { 55 62 [2] 21 7a [2] 66 78 [2] 21 69 [2] 6f 65 [2] 63 6f [2] 74 64 [2] 6f 2a [2] 52 }

  condition:
    any of them
}