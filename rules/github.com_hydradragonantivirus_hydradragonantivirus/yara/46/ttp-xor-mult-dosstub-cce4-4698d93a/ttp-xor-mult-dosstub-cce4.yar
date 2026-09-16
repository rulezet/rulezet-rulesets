rule TTP_XOR_MULT_DOSStub_cce4 {
  strings:
    $key_cce4 = { 98 8c [2] ec 94 [2] ab 96 [2] ec 87 [2] a2 8b [2] ae 81 [2] b9 8a [2] a2 c4 [2] 9f }

  condition:
    any of them
}