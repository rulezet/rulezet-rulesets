rule TTP_XOR_MULT_DOSStub_1aa9 {
  strings:
    $key_1aa9 = { 4e c1 [2] 3a d9 [2] 7d db [2] 3a ca [2] 74 c6 [2] 78 cc [2] 6f c7 [2] 74 89 [2] 49 }

  condition:
    any of them
}