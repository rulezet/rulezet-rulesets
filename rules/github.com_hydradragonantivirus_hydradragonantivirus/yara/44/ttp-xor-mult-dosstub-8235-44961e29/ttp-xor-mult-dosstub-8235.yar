rule TTP_XOR_MULT_DOSStub_8235 {
  strings:
    $key_8235 = { d6 5d [2] a2 45 [2] e5 47 [2] a2 56 [2] ec 5a [2] e0 50 [2] f7 5b [2] ec 15 [2] d1 }

  condition:
    any of them
}