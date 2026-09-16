rule TTP_XOR_MULT_DOSStub_c324 {
  strings:
    $key_c324 = { 97 4c [2] e3 54 [2] a4 56 [2] e3 47 [2] ad 4b [2] a1 41 [2] b6 4a [2] ad 04 [2] 90 }

  condition:
    any of them
}