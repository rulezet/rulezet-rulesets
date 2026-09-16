rule TTP_XOR_MULT_DOSStub_c3f2 {
  strings:
    $key_c3f2 = { 97 9a [2] e3 82 [2] a4 80 [2] e3 91 [2] ad 9d [2] a1 97 [2] b6 9c [2] ad d2 [2] 90 }

  condition:
    any of them
}