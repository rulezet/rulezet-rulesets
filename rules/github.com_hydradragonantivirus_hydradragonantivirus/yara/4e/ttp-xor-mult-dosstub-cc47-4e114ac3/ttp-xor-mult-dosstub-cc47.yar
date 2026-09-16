rule TTP_XOR_MULT_DOSStub_cc47 {
  strings:
    $key_cc47 = { 98 2f [2] ec 37 [2] ab 35 [2] ec 24 [2] a2 28 [2] ae 22 [2] b9 29 [2] a2 67 [2] 9f }

  condition:
    any of them
}