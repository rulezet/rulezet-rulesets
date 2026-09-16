rule TTP_XOR_MULT_DOSStub_820e {
  strings:
    $key_820e = { d6 66 [2] a2 7e [2] e5 7c [2] a2 6d [2] ec 61 [2] e0 6b [2] f7 60 [2] ec 2e [2] d1 }

  condition:
    any of them
}