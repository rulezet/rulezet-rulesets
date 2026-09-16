rule TTP_XOR_MULT_DOSStub_1fa2 {
  strings:
    $key_1fa2 = { 4b ca [2] 3f d2 [2] 78 d0 [2] 3f c1 [2] 71 cd [2] 7d c7 [2] 6a cc [2] 71 82 [2] 4c }

  condition:
    any of them
}