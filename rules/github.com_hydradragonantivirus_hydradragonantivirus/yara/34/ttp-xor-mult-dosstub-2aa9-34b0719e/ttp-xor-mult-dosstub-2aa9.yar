rule TTP_XOR_MULT_DOSStub_2aa9 {
  strings:
    $key_2aa9 = { 7e c1 [2] 0a d9 [2] 4d db [2] 0a ca [2] 44 c6 [2] 48 cc [2] 5f c7 [2] 44 89 [2] 79 }

  condition:
    any of them
}