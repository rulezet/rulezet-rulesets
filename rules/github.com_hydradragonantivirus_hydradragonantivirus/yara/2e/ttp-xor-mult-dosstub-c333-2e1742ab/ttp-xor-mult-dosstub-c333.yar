rule TTP_XOR_MULT_DOSStub_c333 {
  strings:
    $key_c333 = { 97 5b [2] e3 43 [2] a4 41 [2] e3 50 [2] ad 5c [2] a1 56 [2] b6 5d [2] ad 13 [2] 90 }

  condition:
    any of them
}