rule TTP_XOR_MULT_DOSStub_e05f {
  strings:
    $key_e05f = { b4 37 [2] c0 2f [2] 87 2d [2] c0 3c [2] 8e 30 [2] 82 3a [2] 95 31 [2] 8e 7f [2] b3 }

  condition:
    any of them
}