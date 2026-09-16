rule TTP_XOR_MULT_DOSStub_e37f {
  strings:
    $key_e37f = { b7 17 [2] c3 0f [2] 84 0d [2] c3 1c [2] 8d 10 [2] 81 1a [2] 96 11 [2] 8d 5f [2] b0 }

  condition:
    any of them
}