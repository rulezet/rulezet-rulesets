rule TTP_XOR_MULT_DOSStub_cc0b {
  strings:
    $key_cc0b = { 98 63 [2] ec 7b [2] ab 79 [2] ec 68 [2] a2 64 [2] ae 6e [2] b9 65 [2] a2 2b [2] 9f }

  condition:
    any of them
}