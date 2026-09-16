rule TTP_XOR_MULT_DOSStub_cc1e {
  strings:
    $key_cc1e = { 98 76 [2] ec 6e [2] ab 6c [2] ec 7d [2] a2 71 [2] ae 7b [2] b9 70 [2] a2 3e [2] 9f }

  condition:
    any of them
}