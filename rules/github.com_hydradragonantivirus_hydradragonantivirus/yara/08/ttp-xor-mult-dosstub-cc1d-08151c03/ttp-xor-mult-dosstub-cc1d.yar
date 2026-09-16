rule TTP_XOR_MULT_DOSStub_cc1d {
  strings:
    $key_cc1d = { 98 75 [2] ec 6d [2] ab 6f [2] ec 7e [2] a2 72 [2] ae 78 [2] b9 73 [2] a2 3d [2] 9f }

  condition:
    any of them
}