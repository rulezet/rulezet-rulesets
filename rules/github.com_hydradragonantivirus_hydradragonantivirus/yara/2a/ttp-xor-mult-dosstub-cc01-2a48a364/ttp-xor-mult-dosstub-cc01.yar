rule TTP_XOR_MULT_DOSStub_cc01 {
  strings:
    $key_cc01 = { 98 69 [2] ec 71 [2] ab 73 [2] ec 62 [2] a2 6e [2] ae 64 [2] b9 6f [2] a2 21 [2] 9f }

  condition:
    any of them
}