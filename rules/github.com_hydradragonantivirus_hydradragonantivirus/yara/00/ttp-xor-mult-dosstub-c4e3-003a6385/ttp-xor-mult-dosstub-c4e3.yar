rule TTP_XOR_MULT_DOSStub_c4e3 {
  strings:
    $key_c4e3 = { 90 8b [2] e4 93 [2] a3 91 [2] e4 80 [2] aa 8c [2] a6 86 [2] b1 8d [2] aa c3 [2] 97 }

  condition:
    any of them
}