rule TTP_XOR_MULT_DOSStub_c553 {
  strings:
    $key_c553 = { 91 3b [2] e5 23 [2] a2 21 [2] e5 30 [2] ab 3c [2] a7 36 [2] b0 3d [2] ab 73 [2] 96 }

  condition:
    any of them
}