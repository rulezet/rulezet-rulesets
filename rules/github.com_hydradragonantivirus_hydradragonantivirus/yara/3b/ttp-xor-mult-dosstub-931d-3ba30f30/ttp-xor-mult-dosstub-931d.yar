rule TTP_XOR_MULT_DOSStub_931d {
  strings:
    $key_931d = { c7 75 [2] b3 6d [2] f4 6f [2] b3 7e [2] fd 72 [2] f1 78 [2] e6 73 [2] fd 3d [2] c0 }

  condition:
    any of them
}