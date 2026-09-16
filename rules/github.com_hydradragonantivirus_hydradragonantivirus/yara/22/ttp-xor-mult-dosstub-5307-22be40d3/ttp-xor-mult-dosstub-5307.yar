rule TTP_XOR_MULT_DOSStub_5307 {
  strings:
    $key_5307 = { 07 6f [2] 73 77 [2] 34 75 [2] 73 64 [2] 3d 68 [2] 31 62 [2] 26 69 [2] 3d 27 [2] 00 }

  condition:
    any of them
}