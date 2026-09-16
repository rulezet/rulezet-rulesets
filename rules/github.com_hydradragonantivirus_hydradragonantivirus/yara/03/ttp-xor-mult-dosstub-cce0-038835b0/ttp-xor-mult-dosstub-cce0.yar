rule TTP_XOR_MULT_DOSStub_cce0 {
  strings:
    $key_cce0 = { 98 88 [2] ec 90 [2] ab 92 [2] ec 83 [2] a2 8f [2] ae 85 [2] b9 8e [2] a2 c0 [2] 9f }

  condition:
    any of them
}