rule TTP_XOR_MULT_DOSStub_e60b {
  strings:
    $key_e60b = { b2 63 [2] c6 7b [2] 81 79 [2] c6 68 [2] 88 64 [2] 84 6e [2] 93 65 [2] 88 2b [2] b5 }

  condition:
    any of them
}