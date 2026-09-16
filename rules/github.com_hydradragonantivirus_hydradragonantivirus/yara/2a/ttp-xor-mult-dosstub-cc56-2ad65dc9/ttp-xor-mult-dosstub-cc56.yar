rule TTP_XOR_MULT_DOSStub_cc56 {
  strings:
    $key_cc56 = { 98 3e [2] ec 26 [2] ab 24 [2] ec 35 [2] a2 39 [2] ae 33 [2] b9 38 [2] a2 76 [2] 9f }

  condition:
    any of them
}