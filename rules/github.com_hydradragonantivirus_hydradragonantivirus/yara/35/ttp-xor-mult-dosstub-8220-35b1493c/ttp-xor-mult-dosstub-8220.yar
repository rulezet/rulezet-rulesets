rule TTP_XOR_MULT_DOSStub_8220 {
  strings:
    $key_8220 = { d6 48 [2] a2 50 [2] e5 52 [2] a2 43 [2] ec 4f [2] e0 45 [2] f7 4e [2] ec 00 [2] d1 }

  condition:
    any of them
}