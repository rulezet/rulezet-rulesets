rule TTP_XOR_MULT_DOSStub_e653 {
  strings:
    $key_e653 = { b2 3b [2] c6 23 [2] 81 21 [2] c6 30 [2] 88 3c [2] 84 36 [2] 93 3d [2] 88 73 [2] b5 }

  condition:
    any of them
}