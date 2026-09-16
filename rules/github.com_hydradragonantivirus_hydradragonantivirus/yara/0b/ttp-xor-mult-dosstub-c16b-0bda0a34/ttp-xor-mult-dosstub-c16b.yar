rule TTP_XOR_MULT_DOSStub_c16b {
  strings:
    $key_c16b = { 95 03 [2] e1 1b [2] a6 19 [2] e1 08 [2] af 04 [2] a3 0e [2] b4 05 [2] af 4b [2] 92 }

  condition:
    any of them
}