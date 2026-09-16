rule TTP_XOR_MULT_DOSStub_c2f7 {
  strings:
    $key_c2f7 = { 96 9f [2] e2 87 [2] a5 85 [2] e2 94 [2] ac 98 [2] a0 92 [2] b7 99 [2] ac d7 [2] 91 }

  condition:
    any of them
}