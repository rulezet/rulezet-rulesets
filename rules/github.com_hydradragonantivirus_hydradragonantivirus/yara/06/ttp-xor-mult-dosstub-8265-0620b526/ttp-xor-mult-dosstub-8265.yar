rule TTP_XOR_MULT_DOSStub_8265 {
  strings:
    $key_8265 = { d6 0d [2] a2 15 [2] e5 17 [2] a2 06 [2] ec 0a [2] e0 00 [2] f7 0b [2] ec 45 [2] d1 }

  condition:
    any of them
}