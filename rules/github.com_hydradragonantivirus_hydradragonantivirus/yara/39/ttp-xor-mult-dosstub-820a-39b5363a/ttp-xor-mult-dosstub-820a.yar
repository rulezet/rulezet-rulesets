rule TTP_XOR_MULT_DOSStub_820a {
  strings:
    $key_820a = { d6 62 [2] a2 7a [2] e5 78 [2] a2 69 [2] ec 65 [2] e0 6f [2] f7 64 [2] ec 2a [2] d1 }

  condition:
    any of them
}