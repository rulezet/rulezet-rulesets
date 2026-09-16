rule TTP_XOR_MULT_DOSStub_c22f {
  strings:
    $key_c22f = { 96 47 [2] e2 5f [2] a5 5d [2] e2 4c [2] ac 40 [2] a0 4a [2] b7 41 [2] ac 0f [2] 91 }

  condition:
    any of them
}