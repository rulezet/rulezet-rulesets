rule TTP_XOR_MULT_DOSStub_c2a2 {
  strings:
    $key_c2a2 = { 96 ca [2] e2 d2 [2] a5 d0 [2] e2 c1 [2] ac cd [2] a0 c7 [2] b7 cc [2] ac 82 [2] 91 }

  condition:
    any of them
}