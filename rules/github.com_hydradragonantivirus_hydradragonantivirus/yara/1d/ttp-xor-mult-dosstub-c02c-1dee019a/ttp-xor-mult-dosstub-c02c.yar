rule TTP_XOR_MULT_DOSStub_c02c {
  strings:
    $key_c02c = { 94 44 [2] e0 5c [2] a7 5e [2] e0 4f [2] ae 43 [2] a2 49 [2] b5 42 [2] ae 0c [2] 93 }

  condition:
    any of them
}