rule TTP_XOR_MULT_DOSStub_8218 {
  strings:
    $key_8218 = { d6 70 [2] a2 68 [2] e5 6a [2] a2 7b [2] ec 77 [2] e0 7d [2] f7 76 [2] ec 38 [2] d1 }

  condition:
    any of them
}