rule TTP_XOR_MULT_DOSStub_825d {
  strings:
    $key_825d = { d6 35 [2] a2 2d [2] e5 2f [2] a2 3e [2] ec 32 [2] e0 38 [2] f7 33 [2] ec 7d [2] d1 }

  condition:
    any of them
}