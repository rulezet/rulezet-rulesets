rule TTP_XOR_MULT_DOSStub_e61d {
  strings:
    $key_e61d = { b2 75 [2] c6 6d [2] 81 6f [2] c6 7e [2] 88 72 [2] 84 78 [2] 93 73 [2] 88 3d [2] b5 }

  condition:
    any of them
}