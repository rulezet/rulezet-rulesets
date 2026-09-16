rule TTP_XOR_MULT_DOSStub_e633 {
  strings:
    $key_e633 = { b2 5b [2] c6 43 [2] 81 41 [2] c6 50 [2] 88 5c [2] 84 56 [2] 93 5d [2] 88 13 [2] b5 }

  condition:
    any of them
}