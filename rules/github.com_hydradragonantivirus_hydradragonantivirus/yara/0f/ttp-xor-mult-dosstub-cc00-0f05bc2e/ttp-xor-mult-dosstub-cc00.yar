rule TTP_XOR_MULT_DOSStub_cc00 {
  strings:
    $key_cc00 = { 98 68 [2] ec 70 [2] ab 72 [2] ec 63 [2] a2 6f [2] ae 65 [2] b9 6e [2] a2 20 [2] 9f }

  condition:
    any of them
}