rule TTP_XOR_MULT_DOSStub_c60c {
  strings:
    $key_c60c = { 92 64 [2] e6 7c [2] a1 7e [2] e6 6f [2] a8 63 [2] a4 69 [2] b3 62 [2] a8 2c [2] 95 }

  condition:
    any of them
}