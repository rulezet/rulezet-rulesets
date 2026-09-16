rule TTP_XOR_MULT_DOSStub_c35b {
  strings:
    $key_c35b = { 97 33 [2] e3 2b [2] a4 29 [2] e3 38 [2] ad 34 [2] a1 3e [2] b6 35 [2] ad 7b [2] 90 }

  condition:
    any of them
}