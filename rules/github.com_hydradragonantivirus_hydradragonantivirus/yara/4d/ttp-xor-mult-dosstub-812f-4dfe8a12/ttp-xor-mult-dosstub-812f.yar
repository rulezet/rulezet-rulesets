rule TTP_XOR_MULT_DOSStub_812f {
  strings:
    $key_812f = { d5 47 [2] a1 5f [2] e6 5d [2] a1 4c [2] ef 40 [2] e3 4a [2] f4 41 [2] ef 0f [2] d2 }

  condition:
    any of them
}