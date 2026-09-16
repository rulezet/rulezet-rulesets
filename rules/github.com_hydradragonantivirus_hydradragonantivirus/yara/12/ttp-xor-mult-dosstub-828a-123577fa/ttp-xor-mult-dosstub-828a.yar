rule TTP_XOR_MULT_DOSStub_828a {
  strings:
    $key_828a = { d6 e2 [2] a2 fa [2] e5 f8 [2] a2 e9 [2] ec e5 [2] e0 ef [2] f7 e4 [2] ec aa [2] d1 }

  condition:
    any of them
}