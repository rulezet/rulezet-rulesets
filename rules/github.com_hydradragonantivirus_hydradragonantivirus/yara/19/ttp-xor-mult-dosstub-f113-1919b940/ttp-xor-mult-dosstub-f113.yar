rule TTP_XOR_MULT_DOSStub_f113 {
  strings:
    $key_f113 = { a5 7b [2] d1 63 [2] 96 61 [2] d1 70 [2] 9f 7c [2] 93 76 [2] 84 7d [2] 9f 33 [2] a2 }

  condition:
    any of them
}