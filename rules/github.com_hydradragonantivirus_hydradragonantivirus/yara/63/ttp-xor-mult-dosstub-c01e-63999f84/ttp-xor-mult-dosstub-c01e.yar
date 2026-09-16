rule TTP_XOR_MULT_DOSStub_c01e {
  strings:
    $key_c01e = { 94 76 [2] e0 6e [2] a7 6c [2] e0 7d [2] ae 71 [2] a2 7b [2] b5 70 [2] ae 3e [2] 93 }

  condition:
    any of them
}