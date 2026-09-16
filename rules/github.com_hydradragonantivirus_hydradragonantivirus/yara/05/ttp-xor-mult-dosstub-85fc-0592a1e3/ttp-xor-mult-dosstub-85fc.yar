rule TTP_XOR_MULT_DOSStub_85fc {
  strings:
    $key_85fc = { d1 94 [2] a5 8c [2] e2 8e [2] a5 9f [2] eb 93 [2] e7 99 [2] f0 92 [2] eb dc [2] d6 }

  condition:
    any of them
}