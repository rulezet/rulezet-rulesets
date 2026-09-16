rule TTP_XOR_MULT_DOSStub_c2f2 {
  strings:
    $key_c2f2 = { 96 9a [2] e2 82 [2] a5 80 [2] e2 91 [2] ac 9d [2] a0 97 [2] b7 9c [2] ac d2 [2] 91 }

  condition:
    any of them
}