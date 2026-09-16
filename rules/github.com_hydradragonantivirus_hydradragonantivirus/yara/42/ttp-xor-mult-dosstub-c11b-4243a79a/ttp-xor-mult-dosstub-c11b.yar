rule TTP_XOR_MULT_DOSStub_c11b {
  strings:
    $key_c11b = { 95 73 [2] e1 6b [2] a6 69 [2] e1 78 [2] af 74 [2] a3 7e [2] b4 75 [2] af 3b [2] 92 }

  condition:
    any of them
}