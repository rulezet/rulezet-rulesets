rule TTP_XOR_MULT_DOSStub_f153 {
  strings:
    $key_f153 = { a5 3b [2] d1 23 [2] 96 21 [2] d1 30 [2] 9f 3c [2] 93 36 [2] 84 3d [2] 9f 73 [2] a2 }

  condition:
    any of them
}