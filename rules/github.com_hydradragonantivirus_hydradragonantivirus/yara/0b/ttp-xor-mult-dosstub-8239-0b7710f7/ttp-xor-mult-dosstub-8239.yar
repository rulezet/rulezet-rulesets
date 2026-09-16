rule TTP_XOR_MULT_DOSStub_8239 {
  strings:
    $key_8239 = { d6 51 [2] a2 49 [2] e5 4b [2] a2 5a [2] ec 56 [2] e0 5c [2] f7 57 [2] ec 19 [2] d1 }

  condition:
    any of them
}