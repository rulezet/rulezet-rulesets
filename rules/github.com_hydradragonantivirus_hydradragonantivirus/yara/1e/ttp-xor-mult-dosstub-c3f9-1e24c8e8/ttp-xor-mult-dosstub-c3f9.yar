rule TTP_XOR_MULT_DOSStub_c3f9 {
  strings:
    $key_c3f9 = { 97 91 [2] e3 89 [2] a4 8b [2] e3 9a [2] ad 96 [2] a1 9c [2] b6 97 [2] ad d9 [2] 90 }

  condition:
    any of them
}