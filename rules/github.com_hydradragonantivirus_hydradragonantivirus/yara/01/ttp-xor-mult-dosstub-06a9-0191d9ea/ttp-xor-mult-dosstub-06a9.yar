rule TTP_XOR_MULT_DOSStub_06a9 {
  strings:
    $key_06a9 = { 52 c1 [2] 26 d9 [2] 61 db [2] 26 ca [2] 68 c6 [2] 64 cc [2] 73 c7 [2] 68 89 [2] 55 }

  condition:
    any of them
}