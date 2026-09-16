rule TTP_XOR_MULT_DOSStub_cc77 {
  strings:
    $key_cc77 = { 98 1f [2] ec 07 [2] ab 05 [2] ec 14 [2] a2 18 [2] ae 12 [2] b9 19 [2] a2 57 [2] 9f }

  condition:
    any of them
}