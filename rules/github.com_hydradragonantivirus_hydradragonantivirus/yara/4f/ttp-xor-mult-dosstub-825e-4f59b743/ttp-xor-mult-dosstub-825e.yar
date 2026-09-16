rule TTP_XOR_MULT_DOSStub_825e {
  strings:
    $key_825e = { d6 36 [2] a2 2e [2] e5 2c [2] a2 3d [2] ec 31 [2] e0 3b [2] f7 30 [2] ec 7e [2] d1 }

  condition:
    any of them
}