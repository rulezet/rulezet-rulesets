rule TTP_XOR_MULT_DOSStub_e60f {
  strings:
    $key_e60f = { b2 67 [2] c6 7f [2] 81 7d [2] c6 6c [2] 88 60 [2] 84 6a [2] 93 61 [2] 88 2f [2] b5 }

  condition:
    any of them
}