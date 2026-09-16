rule TTP_XOR_MULT_DOSStub_8251 {
  strings:
    $key_8251 = { d6 39 [2] a2 21 [2] e5 23 [2] a2 32 [2] ec 3e [2] e0 34 [2] f7 3f [2] ec 71 [2] d1 }

  condition:
    any of them
}