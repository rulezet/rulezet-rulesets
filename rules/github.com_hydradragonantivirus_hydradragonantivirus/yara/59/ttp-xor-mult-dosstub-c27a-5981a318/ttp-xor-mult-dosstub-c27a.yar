rule TTP_XOR_MULT_DOSStub_c27a {
  strings:
    $key_c27a = { 96 12 [2] e2 0a [2] a5 08 [2] e2 19 [2] ac 15 [2] a0 1f [2] b7 14 [2] ac 5a [2] 91 }

  condition:
    any of them
}