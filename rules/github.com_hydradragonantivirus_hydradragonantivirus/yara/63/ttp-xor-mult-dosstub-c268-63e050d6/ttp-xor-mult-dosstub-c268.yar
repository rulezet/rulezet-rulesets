rule TTP_XOR_MULT_DOSStub_c268 {
  strings:
    $key_c268 = { 96 00 [2] e2 18 [2] a5 1a [2] e2 0b [2] ac 07 [2] a0 0d [2] b7 06 [2] ac 48 [2] 91 }

  condition:
    any of them
}