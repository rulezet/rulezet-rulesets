rule TTP_XOR_MULT_DOSStub_8210 {
  strings:
    $key_8210 = { d6 78 [2] a2 60 [2] e5 62 [2] a2 73 [2] ec 7f [2] e0 75 [2] f7 7e [2] ec 30 [2] d1 }

  condition:
    any of them
}