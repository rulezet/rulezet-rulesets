rule TTP_XOR_MULT_DOSStub_821f {
  strings:
    $key_821f = { d6 77 [2] a2 6f [2] e5 6d [2] a2 7c [2] ec 70 [2] e0 7a [2] f7 71 [2] ec 3f [2] d1 }

  condition:
    any of them
}