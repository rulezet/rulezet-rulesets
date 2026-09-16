rule TTP_XOR_MULT_DOSStub_cc7b {
  strings:
    $key_cc7b = { 98 13 [2] ec 0b [2] ab 09 [2] ec 18 [2] a2 14 [2] ae 1e [2] b9 15 [2] a2 5b [2] 9f }

  condition:
    any of them
}