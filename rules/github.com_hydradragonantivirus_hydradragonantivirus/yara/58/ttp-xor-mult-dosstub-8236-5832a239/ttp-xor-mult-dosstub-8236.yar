rule TTP_XOR_MULT_DOSStub_8236 {
  strings:
    $key_8236 = { d6 5e [2] a2 46 [2] e5 44 [2] a2 55 [2] ec 59 [2] e0 53 [2] f7 58 [2] ec 16 [2] d1 }

  condition:
    any of them
}