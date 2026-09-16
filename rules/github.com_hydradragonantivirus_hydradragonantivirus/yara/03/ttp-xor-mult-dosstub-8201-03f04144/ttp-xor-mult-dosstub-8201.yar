rule TTP_XOR_MULT_DOSStub_8201 {
  strings:
    $key_8201 = { d6 69 [2] a2 71 [2] e5 73 [2] a2 62 [2] ec 6e [2] e0 64 [2] f7 6f [2] ec 21 [2] d1 }

  condition:
    any of them
}