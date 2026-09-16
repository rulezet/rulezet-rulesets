rule TTP_XOR_MULT_DOSStub_48a2 {
  strings:
    $key_48a2 = { 1c ca [2] 68 d2 [2] 2f d0 [2] 68 c1 [2] 26 cd [2] 2a c7 [2] 3d cc [2] 26 82 [2] 1b }

  condition:
    any of them
}