rule TTP_XOR_MULT_DOSStub_cc7e {
  strings:
    $key_cc7e = { 98 16 [2] ec 0e [2] ab 0c [2] ec 1d [2] a2 11 [2] ae 1b [2] b9 10 [2] a2 5e [2] 9f }

  condition:
    any of them
}