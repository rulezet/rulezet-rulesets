rule TTP_XOR_MULT_DOSStub_cc60 {
  strings:
    $key_cc60 = { 98 08 [2] ec 10 [2] ab 12 [2] ec 03 [2] a2 0f [2] ae 05 [2] b9 0e [2] a2 40 [2] 9f }

  condition:
    any of them
}