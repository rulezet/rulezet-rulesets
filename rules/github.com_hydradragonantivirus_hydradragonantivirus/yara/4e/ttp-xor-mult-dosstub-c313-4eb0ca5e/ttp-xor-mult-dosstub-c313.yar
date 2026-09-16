rule TTP_XOR_MULT_DOSStub_c313 {
  strings:
    $key_c313 = { 97 7b [2] e3 63 [2] a4 61 [2] e3 70 [2] ad 7c [2] a1 76 [2] b6 7d [2] ad 33 [2] 90 }

  condition:
    any of them
}