rule TTP_XOR_MULT_DOSStub_922f {
  strings:
    $key_922f = { c6 47 [2] b2 5f [2] f5 5d [2] b2 4c [2] fc 40 [2] f0 4a [2] e7 41 [2] fc 0f [2] c1 }

  condition:
    any of them
}