rule TTP_XOR_MULT_DOSStub_931f {
  strings:
    $key_931f = { c7 77 [2] b3 6f [2] f4 6d [2] b3 7c [2] fd 70 [2] f1 7a [2] e6 71 [2] fd 3f [2] c0 }

  condition:
    any of them
}