rule TTP_XOR_MULT_DOSStub_cc4f {
  strings:
    $key_cc4f = { 98 27 [2] ec 3f [2] ab 3d [2] ec 2c [2] a2 20 [2] ae 2a [2] b9 21 [2] a2 6f [2] 9f }

  condition:
    any of them
}