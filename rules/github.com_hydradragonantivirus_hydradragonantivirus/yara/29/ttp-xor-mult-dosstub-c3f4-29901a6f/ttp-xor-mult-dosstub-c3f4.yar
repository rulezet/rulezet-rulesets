rule TTP_XOR_MULT_DOSStub_c3f4 {
  strings:
    $key_c3f4 = { 97 9c [2] e3 84 [2] a4 86 [2] e3 97 [2] ad 9b [2] a1 91 [2] b6 9a [2] ad d4 [2] 90 }

  condition:
    any of them
}