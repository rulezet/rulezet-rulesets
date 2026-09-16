rule TTP_XOR_MULT_DOSStub_c325 {
  strings:
    $key_c325 = { 97 4d [2] e3 55 [2] a4 57 [2] e3 46 [2] ad 4a [2] a1 40 [2] b6 4b [2] ad 05 [2] 90 }

  condition:
    any of them
}