rule TTP_XOR_MULT_DOSStub_cc26 {
  strings:
    $key_cc26 = { 98 4e [2] ec 56 [2] ab 54 [2] ec 45 [2] a2 49 [2] ae 43 [2] b9 48 [2] a2 06 [2] 9f }

  condition:
    any of them
}