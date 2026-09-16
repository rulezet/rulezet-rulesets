rule TTP_XOR_MULT_DOSStub_d60c {
  strings:
    $key_d60c = { 82 64 [2] f6 7c [2] b1 7e [2] f6 6f [2] b8 63 [2] b4 69 [2] a3 62 [2] b8 2c [2] 85 }

  condition:
    any of them
}