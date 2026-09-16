rule TTP_XOR_MULT_DOSStub_c70e {
  strings:
    $key_c70e = { 93 66 [2] e7 7e [2] a0 7c [2] e7 6d [2] a9 61 [2] a5 6b [2] b2 60 [2] a9 2e [2] 94 }

  condition:
    any of them
}