rule TTP_XOR_MULT_DOSStub_c05e {
  strings:
    $key_c05e = { 94 36 [2] e0 2e [2] a7 2c [2] e0 3d [2] ae 31 [2] a2 3b [2] b5 30 [2] ae 7e [2] 93 }

  condition:
    any of them
}