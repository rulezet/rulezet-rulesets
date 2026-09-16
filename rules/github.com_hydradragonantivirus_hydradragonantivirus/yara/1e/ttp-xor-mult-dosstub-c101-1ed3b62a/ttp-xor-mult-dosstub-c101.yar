rule TTP_XOR_MULT_DOSStub_c101 {
  strings:
    $key_c101 = { 95 69 [2] e1 71 [2] a6 73 [2] e1 62 [2] af 6e [2] a3 64 [2] b4 6f [2] af 21 [2] 92 }

  condition:
    any of them
}