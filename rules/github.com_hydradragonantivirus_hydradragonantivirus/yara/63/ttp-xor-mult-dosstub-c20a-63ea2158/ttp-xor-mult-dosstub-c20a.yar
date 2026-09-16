rule TTP_XOR_MULT_DOSStub_c20a {
  strings:
    $key_c20a = { 96 62 [2] e2 7a [2] a5 78 [2] e2 69 [2] ac 65 [2] a0 6f [2] b7 64 [2] ac 2a [2] 91 }

  condition:
    any of them
}