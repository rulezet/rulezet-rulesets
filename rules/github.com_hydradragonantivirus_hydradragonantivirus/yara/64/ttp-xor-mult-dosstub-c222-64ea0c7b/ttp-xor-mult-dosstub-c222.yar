rule TTP_XOR_MULT_DOSStub_c222 {
  strings:
    $key_c222 = { 96 4a [2] e2 52 [2] a5 50 [2] e2 41 [2] ac 4d [2] a0 47 [2] b7 4c [2] ac 02 [2] 91 }

  condition:
    any of them
}