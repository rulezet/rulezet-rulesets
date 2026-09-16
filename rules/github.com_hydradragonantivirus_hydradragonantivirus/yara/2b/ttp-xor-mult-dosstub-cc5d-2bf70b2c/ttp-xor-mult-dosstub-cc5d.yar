rule TTP_XOR_MULT_DOSStub_cc5d {
  strings:
    $key_cc5d = { 98 35 [2] ec 2d [2] ab 2f [2] ec 3e [2] a2 32 [2] ae 38 [2] b9 33 [2] a2 7d [2] 9f }

  condition:
    any of them
}