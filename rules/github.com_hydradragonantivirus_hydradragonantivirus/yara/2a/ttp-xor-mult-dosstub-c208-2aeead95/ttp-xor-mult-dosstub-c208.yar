rule TTP_XOR_MULT_DOSStub_c208 {
  strings:
    $key_c208 = { 96 60 [2] e2 78 [2] a5 7a [2] e2 6b [2] ac 67 [2] a0 6d [2] b7 66 [2] ac 28 [2] 91 }

  condition:
    any of them
}