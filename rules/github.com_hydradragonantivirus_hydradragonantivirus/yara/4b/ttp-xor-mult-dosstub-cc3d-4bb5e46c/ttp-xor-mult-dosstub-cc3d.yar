rule TTP_XOR_MULT_DOSStub_cc3d {
  strings:
    $key_cc3d = { 98 55 [2] ec 4d [2] ab 4f [2] ec 5e [2] a2 52 [2] ae 58 [2] b9 53 [2] a2 1d [2] 9f }

  condition:
    any of them
}