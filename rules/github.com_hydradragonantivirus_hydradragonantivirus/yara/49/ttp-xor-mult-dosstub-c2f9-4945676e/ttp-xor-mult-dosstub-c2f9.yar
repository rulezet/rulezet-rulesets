rule TTP_XOR_MULT_DOSStub_c2f9 {
  strings:
    $key_c2f9 = { 96 91 [2] e2 89 [2] a5 8b [2] e2 9a [2] ac 96 [2] a0 9c [2] b7 97 [2] ac d9 [2] 91 }

  condition:
    any of them
}