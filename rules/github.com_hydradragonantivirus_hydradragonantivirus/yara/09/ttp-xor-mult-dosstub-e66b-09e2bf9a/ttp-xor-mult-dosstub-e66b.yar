rule TTP_XOR_MULT_DOSStub_e66b {
  strings:
    $key_e66b = { b2 03 [2] c6 1b [2] 81 19 [2] c6 08 [2] 88 04 [2] 84 0e [2] 93 05 [2] 88 4b [2] b5 }

  condition:
    any of them
}