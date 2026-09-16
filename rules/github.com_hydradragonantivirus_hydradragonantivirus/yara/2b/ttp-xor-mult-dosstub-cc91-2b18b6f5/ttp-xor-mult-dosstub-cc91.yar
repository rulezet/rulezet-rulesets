rule TTP_XOR_MULT_DOSStub_cc91 {
  strings:
    $key_cc91 = { 98 f9 [2] ec e1 [2] ab e3 [2] ec f2 [2] a2 fe [2] ae f4 [2] b9 ff [2] a2 b1 [2] 9f }

  condition:
    any of them
}