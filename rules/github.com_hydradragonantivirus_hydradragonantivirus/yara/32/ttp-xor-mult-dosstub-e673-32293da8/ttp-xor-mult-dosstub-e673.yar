rule TTP_XOR_MULT_DOSStub_e673 {
  strings:
    $key_e673 = { b2 1b [2] c6 03 [2] 81 01 [2] c6 10 [2] 88 1c [2] 84 16 [2] 93 1d [2] 88 53 [2] b5 }

  condition:
    any of them
}