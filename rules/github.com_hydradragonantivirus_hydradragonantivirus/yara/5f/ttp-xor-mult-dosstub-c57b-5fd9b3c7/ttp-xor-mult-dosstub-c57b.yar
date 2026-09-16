rule TTP_XOR_MULT_DOSStub_c57b {
  strings:
    $key_c57b = { 91 13 [2] e5 0b [2] a2 09 [2] e5 18 [2] ab 14 [2] a7 1e [2] b0 15 [2] ab 5b [2] 96 }

  condition:
    any of them
}