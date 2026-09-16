rule TTP_XOR_MULT_DOSStub_c173 {
  strings:
    $key_c173 = { 95 1b [2] e1 03 [2] a6 01 [2] e1 10 [2] af 1c [2] a3 16 [2] b4 1d [2] af 53 [2] 92 }

  condition:
    any of them
}