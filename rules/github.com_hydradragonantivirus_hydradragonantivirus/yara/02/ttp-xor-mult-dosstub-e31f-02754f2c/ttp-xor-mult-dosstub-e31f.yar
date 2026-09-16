rule TTP_XOR_MULT_DOSStub_e31f {
  strings:
    $key_e31f = { b7 77 [2] c3 6f [2] 84 6d [2] c3 7c [2] 8d 70 [2] 81 7a [2] 96 71 [2] 8d 3f [2] b0 }

  condition:
    any of them
}