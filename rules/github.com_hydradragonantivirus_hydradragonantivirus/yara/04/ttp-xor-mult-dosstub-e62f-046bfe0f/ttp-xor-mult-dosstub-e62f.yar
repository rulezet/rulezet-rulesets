rule TTP_XOR_MULT_DOSStub_e62f {
  strings:
    $key_e62f = { b2 47 [2] c6 5f [2] 81 5d [2] c6 4c [2] 88 40 [2] 84 4a [2] 93 41 [2] 88 0f [2] b5 }

  condition:
    any of them
}