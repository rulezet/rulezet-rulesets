rule TTP_XOR_MULT_DOSStub_933a {
  strings:
    $key_933a = { c7 52 [2] b3 4a [2] f4 48 [2] b3 59 [2] fd 55 [2] f1 5f [2] e6 54 [2] fd 1a [2] c0 }

  condition:
    any of them
}