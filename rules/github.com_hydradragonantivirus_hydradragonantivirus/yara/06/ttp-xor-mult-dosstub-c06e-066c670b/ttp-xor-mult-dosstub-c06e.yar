rule TTP_XOR_MULT_DOSStub_c06e {
  strings:
    $key_c06e = { 94 06 [2] e0 1e [2] a7 1c [2] e0 0d [2] ae 01 [2] a2 0b [2] b5 00 [2] ae 4e [2] 93 }

  condition:
    any of them
}