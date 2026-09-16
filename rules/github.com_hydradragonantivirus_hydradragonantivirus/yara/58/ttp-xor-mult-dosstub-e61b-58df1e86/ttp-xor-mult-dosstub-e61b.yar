rule TTP_XOR_MULT_DOSStub_e61b {
  strings:
    $key_e61b = { b2 73 [2] c6 6b [2] 81 69 [2] c6 78 [2] 88 74 [2] 84 7e [2] 93 75 [2] 88 3b [2] b5 }

  condition:
    any of them
}