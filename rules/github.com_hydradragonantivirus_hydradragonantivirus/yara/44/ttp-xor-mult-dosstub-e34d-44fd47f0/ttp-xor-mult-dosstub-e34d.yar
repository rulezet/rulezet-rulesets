rule TTP_XOR_MULT_DOSStub_e34d {
  strings:
    $key_e34d = { b7 25 [2] c3 3d [2] 84 3f [2] c3 2e [2] 8d 22 [2] 81 28 [2] 96 23 [2] 8d 6d [2] b0 }

  condition:
    any of them
}