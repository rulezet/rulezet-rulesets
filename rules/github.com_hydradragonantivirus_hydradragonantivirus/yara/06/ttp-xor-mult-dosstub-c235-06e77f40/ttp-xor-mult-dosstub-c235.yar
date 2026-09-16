rule TTP_XOR_MULT_DOSStub_c235 {
  strings:
    $key_c235 = { 96 5d [2] e2 45 [2] a5 47 [2] e2 56 [2] ac 5a [2] a0 50 [2] b7 5b [2] ac 15 [2] 91 }

  condition:
    any of them
}