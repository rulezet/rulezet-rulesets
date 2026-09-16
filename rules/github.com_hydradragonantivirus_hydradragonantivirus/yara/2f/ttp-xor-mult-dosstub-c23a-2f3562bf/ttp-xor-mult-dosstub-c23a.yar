rule TTP_XOR_MULT_DOSStub_c23a {
  strings:
    $key_c23a = { 96 52 [2] e2 4a [2] a5 48 [2] e2 59 [2] ac 55 [2] a0 5f [2] b7 54 [2] ac 1a [2] 91 }

  condition:
    any of them
}