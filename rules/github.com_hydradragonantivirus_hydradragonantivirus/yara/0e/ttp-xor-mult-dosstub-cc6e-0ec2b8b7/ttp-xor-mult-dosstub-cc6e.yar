rule TTP_XOR_MULT_DOSStub_cc6e {
  strings:
    $key_cc6e = { 98 06 [2] ec 1e [2] ab 1c [2] ec 0d [2] a2 01 [2] ae 0b [2] b9 00 [2] a2 4e [2] 9f }

  condition:
    any of them
}