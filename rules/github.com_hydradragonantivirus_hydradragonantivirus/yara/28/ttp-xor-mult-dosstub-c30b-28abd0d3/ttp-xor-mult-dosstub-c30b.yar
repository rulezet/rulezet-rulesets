rule TTP_XOR_MULT_DOSStub_c30b {
  strings:
    $key_c30b = { 97 63 [2] e3 7b [2] a4 79 [2] e3 68 [2] ad 64 [2] a1 6e [2] b6 65 [2] ad 2b [2] 90 }

  condition:
    any of them
}