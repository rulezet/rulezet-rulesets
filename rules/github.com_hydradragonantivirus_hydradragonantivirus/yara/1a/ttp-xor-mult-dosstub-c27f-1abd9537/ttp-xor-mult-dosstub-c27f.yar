rule TTP_XOR_MULT_DOSStub_c27f {
  strings:
    $key_c27f = { 96 17 [2] e2 0f [2] a5 0d [2] e2 1c [2] ac 10 [2] a0 1a [2] b7 11 [2] ac 5f [2] 91 }

  condition:
    any of them
}