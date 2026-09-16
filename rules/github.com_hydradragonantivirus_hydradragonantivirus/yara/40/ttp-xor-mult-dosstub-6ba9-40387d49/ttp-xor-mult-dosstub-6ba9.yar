rule TTP_XOR_MULT_DOSStub_6ba9 {
  strings:
    $key_6ba9 = { 3f c1 [2] 4b d9 [2] 0c db [2] 4b ca [2] 05 c6 [2] 09 cc [2] 1e c7 [2] 05 89 [2] 38 }

  condition:
    any of them
}