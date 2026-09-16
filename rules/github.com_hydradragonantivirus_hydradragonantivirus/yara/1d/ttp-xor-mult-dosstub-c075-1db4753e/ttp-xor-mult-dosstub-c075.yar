rule TTP_XOR_MULT_DOSStub_c075 {
  strings:
    $key_c075 = { 94 1d [2] e0 05 [2] a7 07 [2] e0 16 [2] ae 1a [2] a2 10 [2] b5 1b [2] ae 55 [2] 93 }

  condition:
    any of them
}