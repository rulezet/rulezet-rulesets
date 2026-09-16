rule TTP_XOR_MULT_DOSStub_8214 {
  strings:
    $key_8214 = { d6 7c [2] a2 64 [2] e5 66 [2] a2 77 [2] ec 7b [2] e0 71 [2] f7 7a [2] ec 34 [2] d1 }

  condition:
    any of them
}