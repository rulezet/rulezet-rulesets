rule TTP_XOR_MULT_DOSStub_8238 {
  strings:
    $key_8238 = { d6 50 [2] a2 48 [2] e5 4a [2] a2 5b [2] ec 57 [2] e0 5d [2] f7 56 [2] ec 18 [2] d1 }

  condition:
    any of them
}