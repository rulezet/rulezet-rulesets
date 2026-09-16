rule TTP_XOR_MULT_DOSStub_7155 {
  strings:
    $key_7155 = { 25 3d [2] 51 25 [2] 16 27 [2] 51 36 [2] 1f 3a [2] 13 30 [2] 04 3b [2] 1f 75 [2] 22 }

  condition:
    any of them
}