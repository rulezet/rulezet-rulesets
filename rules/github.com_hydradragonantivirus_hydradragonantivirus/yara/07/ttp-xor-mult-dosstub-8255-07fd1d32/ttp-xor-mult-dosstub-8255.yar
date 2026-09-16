rule TTP_XOR_MULT_DOSStub_8255 {
  strings:
    $key_8255 = { d6 3d [2] a2 25 [2] e5 27 [2] a2 36 [2] ec 3a [2] e0 30 [2] f7 3b [2] ec 75 [2] d1 }

  condition:
    any of them
}