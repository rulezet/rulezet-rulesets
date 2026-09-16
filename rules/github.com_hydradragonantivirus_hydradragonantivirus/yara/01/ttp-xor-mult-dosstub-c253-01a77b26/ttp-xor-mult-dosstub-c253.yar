rule TTP_XOR_MULT_DOSStub_c253 {
  strings:
    $key_c253 = { 96 3b [2] e2 23 [2] a5 21 [2] e2 30 [2] ac 3c [2] a0 36 [2] b7 3d [2] ac 73 [2] 91 }

  condition:
    any of them
}