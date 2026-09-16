rule TTP_XOR_MULT_DOSStub_c308 {
  strings:
    $key_c308 = { 97 60 [2] e3 78 [2] a4 7a [2] e3 6b [2] ad 67 [2] a1 6d [2] b6 66 [2] ad 28 [2] 90 }

  condition:
    any of them
}