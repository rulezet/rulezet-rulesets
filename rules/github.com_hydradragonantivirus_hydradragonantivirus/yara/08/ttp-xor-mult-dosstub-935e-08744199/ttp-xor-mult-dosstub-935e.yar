rule TTP_XOR_MULT_DOSStub_935e {
  strings:
    $key_935e = { c7 36 [2] b3 2e [2] f4 2c [2] b3 3d [2] fd 31 [2] f1 3b [2] e6 30 [2] fd 7e [2] c0 }

  condition:
    any of them
}