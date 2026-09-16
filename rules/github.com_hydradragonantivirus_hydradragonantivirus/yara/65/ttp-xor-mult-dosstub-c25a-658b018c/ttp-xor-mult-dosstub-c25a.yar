rule TTP_XOR_MULT_DOSStub_c25a {
  strings:
    $key_c25a = { 96 32 [2] e2 2a [2] a5 28 [2] e2 39 [2] ac 35 [2] a0 3f [2] b7 34 [2] ac 7a [2] 91 }

  condition:
    any of them
}