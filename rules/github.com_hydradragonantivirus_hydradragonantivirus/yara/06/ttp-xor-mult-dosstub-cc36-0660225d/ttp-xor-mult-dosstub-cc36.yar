rule TTP_XOR_MULT_DOSStub_cc36 {
  strings:
    $key_cc36 = { 98 5e [2] ec 46 [2] ab 44 [2] ec 55 [2] a2 59 [2] ae 53 [2] b9 58 [2] a2 16 [2] 9f }

  condition:
    any of them
}