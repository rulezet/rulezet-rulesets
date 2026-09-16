rule TTP_XOR_MULT_DOSStub_935f {
  strings:
    $key_935f = { c7 37 [2] b3 2f [2] f4 2d [2] b3 3c [2] fd 30 [2] f1 3a [2] e6 31 [2] fd 7f [2] c0 }

  condition:
    any of them
}