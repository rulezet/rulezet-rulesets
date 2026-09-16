rule TTP_XOR_MULT_DOSStub_c02f {
  strings:
    $key_c02f = { 94 47 [2] e0 5f [2] a7 5d [2] e0 4c [2] ae 40 [2] a2 4a [2] b5 41 [2] ae 0f [2] 93 }

  condition:
    any of them
}