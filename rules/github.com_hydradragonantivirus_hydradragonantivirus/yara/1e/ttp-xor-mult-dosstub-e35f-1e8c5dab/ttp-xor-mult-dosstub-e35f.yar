rule TTP_XOR_MULT_DOSStub_e35f {
  strings:
    $key_e35f = { b7 37 [2] c3 2f [2] 84 2d [2] c3 3c [2] 8d 30 [2] 81 3a [2] 96 31 [2] 8d 7f [2] b0 }

  condition:
    any of them
}