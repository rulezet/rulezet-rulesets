rule TTP_XOR_MULT_DOSStub_c028 {
  strings:
    $key_c028 = { 94 40 [2] e0 58 [2] a7 5a [2] e0 4b [2] ae 47 [2] a2 4d [2] b5 46 [2] ae 08 [2] 93 }

  condition:
    any of them
}