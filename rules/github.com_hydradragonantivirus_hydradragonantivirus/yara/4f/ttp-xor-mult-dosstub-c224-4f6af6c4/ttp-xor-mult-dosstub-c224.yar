rule TTP_XOR_MULT_DOSStub_c224 {
  strings:
    $key_c224 = { 96 4c [2] e2 54 [2] a5 56 [2] e2 47 [2] ac 4b [2] a0 41 [2] b7 4a [2] ac 04 [2] 91 }

  condition:
    any of them
}