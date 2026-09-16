rule TTP_XOR_MULT_DOSStub_c0a8 {
  strings:
    $key_c0a8 = { 94 c0 [2] e0 d8 [2] a7 da [2] e0 cb [2] ae c7 [2] a2 cd [2] b5 c6 [2] ae 88 [2] 93 }

  condition:
    any of them
}