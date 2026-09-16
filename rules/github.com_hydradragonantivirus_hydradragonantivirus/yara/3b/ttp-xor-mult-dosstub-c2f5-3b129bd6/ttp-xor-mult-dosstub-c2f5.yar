rule TTP_XOR_MULT_DOSStub_c2f5 {
  strings:
    $key_c2f5 = { 96 9d [2] e2 85 [2] a5 87 [2] e2 96 [2] ac 9a [2] a0 90 [2] b7 9b [2] ac d5 [2] 91 }

  condition:
    any of them
}