rule TTP_XOR_MULT_DOSStub_c002 {
  strings:
    $key_c002 = { 94 6a [2] e0 72 [2] a7 70 [2] e0 61 [2] ae 6d [2] a2 67 [2] b5 6c [2] ae 22 [2] 93 }

  condition:
    any of them
}