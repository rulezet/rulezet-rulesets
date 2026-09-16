rule TTP_XOR_MULT_DOSStub_c22a {
  strings:
    $key_c22a = { 96 42 [2] e2 5a [2] a5 58 [2] e2 49 [2] ac 45 [2] a0 4f [2] b7 44 [2] ac 0a [2] 91 }

  condition:
    any of them
}