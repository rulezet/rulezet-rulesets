rule TTP_XOR_MULT_DOSStub_c0e3 {
  strings:
    $key_c0e3 = { 94 8b [2] e0 93 [2] a7 91 [2] e0 80 [2] ae 8c [2] a2 86 [2] b5 8d [2] ae c3 [2] 93 }

  condition:
    any of them
}