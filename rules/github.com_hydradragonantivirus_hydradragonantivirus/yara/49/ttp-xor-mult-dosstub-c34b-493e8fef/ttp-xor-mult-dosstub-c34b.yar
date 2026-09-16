rule TTP_XOR_MULT_DOSStub_c34b {
  strings:
    $key_c34b = { 97 23 [2] e3 3b [2] a4 39 [2] e3 28 [2] ad 24 [2] a1 2e [2] b6 25 [2] ad 6b [2] 90 }

  condition:
    any of them
}