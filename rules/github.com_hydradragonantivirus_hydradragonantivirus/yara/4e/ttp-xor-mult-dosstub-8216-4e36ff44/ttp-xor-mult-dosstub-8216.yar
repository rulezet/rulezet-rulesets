rule TTP_XOR_MULT_DOSStub_8216 {
  strings:
    $key_8216 = { d6 7e [2] a2 66 [2] e5 64 [2] a2 75 [2] ec 79 [2] e0 73 [2] f7 78 [2] ec 36 [2] d1 }

  condition:
    any of them
}