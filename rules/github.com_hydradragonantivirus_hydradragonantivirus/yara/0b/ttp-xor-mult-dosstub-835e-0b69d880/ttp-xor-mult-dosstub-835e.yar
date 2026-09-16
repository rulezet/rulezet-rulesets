rule TTP_XOR_MULT_DOSStub_835e {
  strings:
    $key_835e = { d7 36 [2] a3 2e [2] e4 2c [2] a3 3d [2] ed 31 [2] e1 3b [2] f6 30 [2] ed 7e [2] d0 }

  condition:
    any of them
}