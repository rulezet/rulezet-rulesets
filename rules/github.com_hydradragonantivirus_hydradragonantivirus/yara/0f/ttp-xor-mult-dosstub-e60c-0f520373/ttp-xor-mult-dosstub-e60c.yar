rule TTP_XOR_MULT_DOSStub_e60c {
  strings:
    $key_e60c = { b2 64 [2] c6 7c [2] 81 7e [2] c6 6f [2] 88 63 [2] 84 69 [2] 93 62 [2] 88 2c [2] b5 }

  condition:
    any of them
}