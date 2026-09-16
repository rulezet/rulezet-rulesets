rule TTP_XOR_MULT_DOSStub_cc9a {
  strings:
    $key_cc9a = { 98 f2 [2] ec ea [2] ab e8 [2] ec f9 [2] a2 f5 [2] ae ff [2] b9 f4 [2] a2 ba [2] 9f }

  condition:
    any of them
}