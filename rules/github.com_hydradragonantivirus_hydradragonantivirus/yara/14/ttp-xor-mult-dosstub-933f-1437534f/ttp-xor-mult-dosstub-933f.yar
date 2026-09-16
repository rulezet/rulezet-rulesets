rule TTP_XOR_MULT_DOSStub_933f {
  strings:
    $key_933f = { c7 57 [2] b3 4f [2] f4 4d [2] b3 5c [2] fd 50 [2] f1 5a [2] e6 51 [2] fd 1f [2] c0 }

  condition:
    any of them
}